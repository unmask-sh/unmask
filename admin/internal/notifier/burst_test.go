package notifier

import (
	"strings"
	"testing"
	"time"
)

// fakeClock is the clock the burst count reads in these tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) add(sec int64)  { c.t = c.t.Add(time.Duration(sec) * time.Second) }

// warmUp starts n counting and runs it through the hour a burst is measured
// against, per challenges in each five minutes of it (0: none after the one
// that starts the count), and leaves the clock two minutes into the five
// after, the first a burst can be told in.
func warmUp(n *Notifier, per int) *fakeClock {
	c := &fakeClock{t: time.Date(2026, 10, 17, 1, 2, 0, 0, time.UTC)}
	n.now = c.now
	n.ChallengeServed() // the count begins inside this bucket: it is partial
	for i := 0; i < burstHistory; i++ {
		c.add(burstBucket)
		serve(n, per)
	}
	c.add(burstBucket)
	return c
}

func serve(n *Notifier, k int) {
	for i := 0; i < k; i++ {
		n.ChallengeServed()
	}
}

// TestBurstAgainstTheHourBefore: a busy site's ordinary five minutes are far
// over the floor and are not a burst; ten times them is, once.
func TestBurstAgainstTheHourBefore(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	n := New(Config{BurstThresholdPer5m: 50}).WithInbox(ib)
	warmUp(n, 400)
	serve(n, 3999)
	ib.none(t, "just under ten times the hour's average")
	n.ChallengeServed()
	f := ib.next(t, "ten times the hour's average")
	if f["count_per_5m"] != int64(4000) || f["threshold"] != int64(4000) || f["baseline_per_5m"] != int64(400) {
		t.Errorf("burst fields: %v", f)
	}
	serve(n, 1000)
	ib.none(t, "the same five minutes again")
}

// TestBurstFloor: on a quiet site ten times next to nothing is not a burst;
// the operator's number is the least that is.
func TestBurstFloor(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	n := New(Config{BurstThresholdPer5m: 50}).WithInbox(ib)
	warmUp(n, 1)
	serve(n, 49)
	ib.none(t, "forty-nine times the average, under the floor")
	n.ChallengeServed()
	f := ib.next(t, "the floor")
	if f["count_per_5m"] != int64(50) || f["threshold"] != int64(50) || f["baseline_per_5m"] != int64(1) {
		t.Errorf("burst fields: %v", f)
	}
}

// TestBurstWaitsForTheHour: the first hour of counting has no hour before it,
// so nothing in it is a burst, however many challenges come; the hour it
// counted is then what the next five minutes are measured against.
func TestBurstWaitsForTheHour(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	n := New(Config{BurstThresholdPer5m: 5}).WithInbox(ib)
	c := &fakeClock{t: time.Date(2026, 10, 17, 1, 2, 0, 0, time.UTC)}
	n.now = c.now
	for i := 0; i <= burstHistory; i++ { // the partial bucket and twelve whole ones
		serve(n, 1000)
		c.add(burstBucket)
	}
	ib.none(t, "a burst in the first hour")
	serve(n, 9999)
	ib.none(t, "just under ten times the first hour")
	n.ChallengeServed()
	if f := ib.next(t, "ten times the first hour"); f["baseline_per_5m"] != int64(1000) {
		t.Errorf("burst fields: %v", f)
	}
}

// TestBurstQuietAfterANotice: one surge, one notice -- the five minutes after
// it are over their mark too and say nothing -- and an hour on, the surge is
// part of the average the next one is measured against.
func TestBurstQuietAfterANotice(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	n := New(Config{BurstThresholdPer5m: 5}).WithInbox(ib)
	c := warmUp(n, 1)
	serve(n, 10)
	ib.next(t, "the surge")
	c.add(burstBucket)
	serve(n, 20) // the hour before is eleven ones and the ten: the mark is 18
	ib.none(t, "five minutes after the notice")
	c.add(12 * burstBucket) // an hour without a challenge
	serve(n, 16)
	ib.none(t, "under the mark an hour on")
	n.ChallengeServed() // the hour before is the twenty and eleven empty buckets: the mark is 17
	if f := ib.next(t, "a surge an hour on"); f["threshold"] != int64(17) || f["baseline_per_5m"] != int64(2) {
		t.Errorf("burst fields: %v", f)
	}
}

// bodyMailer records the alert mail's body.
type bodyMailer struct{ sent chan string }

func (m *bodyMailer) Enabled() bool { return true }
func (m *bodyMailer) Send(to, subject, body string) error {
	m.sent <- subject + "\n" + body
	return nil
}
func (m *bodyMailer) SendAlt(to, subject, text, html string) error { return m.Send(to, subject, text) }

// TestBurstMailSaysTheHourBefore: with the switch on, the mail gives the
// count and the average it was measured against.
func TestBurstMailSaysTheHourBefore(t *testing.T) {
	m := &bodyMailer{sent: make(chan string, 4)}
	n := New(Config{ChallengeBurst: true, BurstThresholdPer5m: 50, Sites: "blog"}).
		WithMail(m, func() []Recipient { return []Recipient{{Email: "ops@example.com"}} }, nil)
	warmUp(n, 30)
	serve(n, 300)
	select {
	case got := <-m.sent:
		for _, want := range []string{"[unmask:blog] challenge burst: 300/5min", "300 challenges within 5 minutes", "averaged 30 per 5 minutes"} {
			if !strings.Contains(got, want) {
				t.Errorf("mail lacks %q:\n%s", want, got)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the burst mail did not go out")
	}
}

// TestBurstCountsWithNoFloor: with the floor at 0 nothing is told, but the
// count goes on, so a floor set again measures against the real hour before
// and not an empty one.
func TestBurstCountsWithNoFloor(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	n := New(Config{BurstThresholdPer5m: 50}).WithInbox(ib)
	c := warmUp(n, 100)
	n.SetConfig(Config{})
	for i := 0; i < 2*burstHistory; i++ { // two hours of the same traffic with no floor
		serve(n, 100)
		c.add(burstBucket)
	}
	n.SetConfig(Config{BurstThresholdPer5m: 50})
	serve(n, 100)
	ib.none(t, "an ordinary five minutes once the floor is back")
	serve(n, 900)
	ib.next(t, "ten times the hour counted while there was no floor")
}
