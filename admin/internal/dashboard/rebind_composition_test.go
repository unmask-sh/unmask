package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A pass earned by re-binding a credential onto a new address is its own
// share, not part of the human one.
//
// It used to be indistinguishable from a CAPTCHA pass, because the plugin read
// the cookie's shape rather than the kind the admin signed into it, and both
// solved-CAPTCHA and re-bound entries have three segments.  Measured on a
// production install: a crawler passing entirely by roaming produced a steady
// 1-3 "CAPTCHA passes" per five minutes for days while the proof-of-work
// counters it never touched read zero -- so the dashboard reported the
// challenge as unbroken while a day's worth of requests walked through it.
func TestTrafficRequestsSplitsRebindFromHuman(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}

	minute := time.Now().Unix() / 60
	for _, r := range []struct {
		kind string
		cnt  int
	}{
		{"total", 100},
		{"crawler_pass", 10},
		{"bypass_pass", 5},
		{"challenge_served", 20},
		{"pow", 30},
		{"captcha", 5},
		{"rebind", 25},
		{"passthrough", 3},
	} {
		if _, err := d.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
			VALUES (?, 'default', ?, ?)`, minute, r.kind, r.cnt); err != nil {
			t.Fatal(err)
		}
	}

	c, err := TrafficRequests(context.Background(), d, 60, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Passed != 35 {
		t.Errorf("human share must count only solved passes (pow+captcha): got %d, want 35", c.Passed)
	}
	// The landing KPIs print the two kinds separately, next to solve counts
	// that they are NOT: a solve is counted once, a cookie is counted every
	// request it admits.  Folding the kinds together here would put one number
	// under both cards.
	if c.PowPass != 30 || c.CaptchaPass != 5 {
		t.Errorf("per-kind split: pow=%d captcha=%d, want 30/5", c.PowPass, c.CaptchaPass)
	}
	if c.Rebound != 25 {
		t.Errorf("re-bound passes = %d, want 25", c.Rebound)
	}
	// The segments are shares of one total, and this is the invariant that
	// breaks first when a new kind is added without being placed: the residue
	// silently absorbs it, or goes negative.
	sum := c.Benign + c.Bypassed + c.Challenged + c.Passed + c.Rebound + c.Passthrough + c.Unchallenged
	if sum != c.Total {
		t.Fatalf("parts %d != total %d (rebind unplaced in the composition)", sum, c.Total)
	}
	if c.Passthrough != 3 {
		t.Errorf("passthrough = %d, want 3 (a cookie handed out while enforcement was off "+
			"is not a solve and not an exemption)", c.Passthrough)
	}
	if c.Unchallenged != 2 {
		t.Errorf("residue = %d, want 2", c.Unchallenged)
	}
}
