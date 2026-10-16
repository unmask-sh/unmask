package notifier

import (
	"testing"
	"time"
)

// chanInbox records what reaches the admin's list.
type chanInbox struct{ got chan map[string]any }

func (c *chanInbox) Add(event string, fields map[string]any) {
	fields["_event"] = event
	c.got <- fields
}

func (c *chanInbox) next(t *testing.T, what string) map[string]any {
	t.Helper()
	select {
	case f := <-c.got:
		return f
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not reach the list", what)
		return nil
	}
}

func (c *chanInbox) none(t *testing.T, what string) {
	t.Helper()
	select {
	case f := <-c.got:
		t.Fatalf("%s reached the list: %v", what, f)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestInboxGetsEveryEventWhateverTheSwitches: the list is the channel every
// install has, so the master switch, the per-event switches and the channel
// pauses -- all off, the shipped default for bans and bursts -- do not keep an
// event from it, while they do keep it from the webhook and the mail.
func TestInboxGetsEveryEventWhateverTheSwitches(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	m := &chanMailer{sent: make(chan string, 8)}
	n := New(Config{Disabled: true, Sites: "blog", BurstThresholdPer5m: 3}).
		WithMail(m, func() []Recipient { return []Recipient{{Email: "ops@example.com"}} }, nil).
		WithInbox(ib)

	n.BanCreated("203.0.113.7", "t13d", "honeypot", "hit /wp-login.php", "")
	f := ib.next(t, "the ban")
	if f["_event"] != EventBanCreated || f["ip"] != "203.0.113.7" || f["source"] != "honeypot" || f["site"] != "blog" {
		t.Errorf("ban fields: %v", f)
	}

	for i := 0; i < 3; i++ {
		n.ChallengeServed()
	}
	f = ib.next(t, "the burst")
	if f["_event"] != EventChallengeBurst || f["count_per_5m"] != int64(3) || f["threshold"] != int64(3) {
		t.Errorf("burst fields: %v", f)
	}
	n.ChallengeServed() // over the threshold again inside the window: one burst per window
	ib.none(t, "a second burst in the window")

	n.OverBlock(tripReport)
	f = ib.next(t, "the trip")
	if f["_event"] != EventOverBlock || f["tripped"] != true || f["min_stuck"] != 3 || f["min_percent"] != 50 {
		t.Errorf("over-block fields: %v", f)
	}

	n.AdvisorDigest(2, 5, "digest body")
	f = ib.next(t, "the digest")
	if f["_event"] != EventAdvisorDigest || f["new_candidates"] != 2 || f["total_candidates"] != 5 {
		t.Errorf("digest fields: %v", f)
	}

	select {
	case s := <-m.sent:
		t.Errorf("the master switch is off, but mail went out: %s", s)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestBurstCountsWithoutTheSwitch: with the burst notification off (the
// default) the count still runs for the list, and the mail stays off.
func TestBurstCountsWithoutTheSwitch(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	m := &chanMailer{sent: make(chan string, 8)}
	n := New(Config{BurstThresholdPer5m: 2}).
		WithMail(m, func() []Recipient { return []Recipient{{Email: "ops@example.com"}} }, nil).
		WithInbox(ib)
	n.ChallengeServed()
	ib.none(t, "a count below the threshold")
	n.ChallengeServed()
	ib.next(t, "the burst")
	select {
	case s := <-m.sent:
		t.Errorf("challenge_burst is off, but mail went out: %s", s)
	case <-time.After(150 * time.Millisecond):
	}

	// No threshold: nothing is counted, nothing reaches the list.
	n2 := New(Config{}).WithInbox(ib)
	for i := 0; i < 100; i++ {
		n2.ChallengeServed()
	}
	ib.none(t, "a burst with no threshold")
}

// TestNoInbox: a notifier without a list (no database) still sends.
func TestNoInbox(t *testing.T) {
	m := &chanMailer{sent: make(chan string, 8)}
	n := New(Config{BanEvents: true}).WithMail(m, func() []Recipient { return []Recipient{{Email: "ops@example.com"}} }, nil)
	n.BanCreated("203.0.113.7", "", "manual", "", "alice")
	select {
	case <-m.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("the ban mail did not go out")
	}
}
