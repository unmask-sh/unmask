package events

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// seedStuck writes one of each case StuckVisitors has to tell apart, all in
// the last hour unless said otherwise.
func seedStuck(t *testing.T, d *db.DB) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Add(-10 * time.Minute)
	ins := func(ip, site, phase, path, reason string, at time.Time) {
		t.Helper()
		pl := map[string]any{"orig_path": path}
		if reason != "" {
			pl["force_reason"] = reason
		}
		if err := Insert(ctx, d, &Event{IPPacked: PackIP(ip), Site: site, Phase: phase, UserAgent: "Mozilla/5.0 Chrome/126",
			Payload: pl, OccurredAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	// Ten addresses ran the challenge.
	for i := 1; i <= 10; i++ {
		ins(fmt.Sprintf("203.0.113.%d", i), "s1", "load", "/", "", now)
	}
	// .1: passed /a, and /a was challenged again two seconds later: stuck.
	ins("203.0.113.1", "s1", "bv_pow_only", "/a", "", now)
	ins("203.0.113.1", "s1", "serve", "/a", "none", now.Add(2*time.Second))
	ins("203.0.113.1", "s1", "serve", "/a", "none", now.Add(3*time.Second))
	// .2: passed /b, challenged on /b ten minutes later (the pass expired, a
	// cookie cleared): not stuck.
	ins("203.0.113.2", "s1", "bv_pow_only", "/b", "", now.Add(-10*time.Minute))
	ins("203.0.113.2", "s1", "serve", "/b", "none", now)
	// .3: passed /c, challenged on another page: someone else behind the
	// address, or another tab -- not stuck.
	ins("203.0.113.3", "s1", "bv_captcha_only", "/c", "", now)
	ins("203.0.113.3", "s1", "serve", "/d", "none", now.Add(2*time.Second))
	// .4: passed on s1, challenged on s2: another site's cookie -- not stuck.
	ins("203.0.113.4", "s1", "bv_pow_then_captcha", "/e", "", now)
	ins("203.0.113.4", "s2", "serve", "/e", "none", now.Add(2*time.Second))
	// .5: passed, then challenged on purpose (the reuse cap): not stuck.
	ins("203.0.113.5", "s1", "bv_pow_only", "/f", "", now)
	ins("203.0.113.5", "s1", "serve", "/f", "reuse_limit", now.Add(2*time.Second))
	// .6: its answers failed verification twice: stuck.
	ins("203.0.113.6", "s1", "verify_ng", "/g", "", now)
	ins("203.0.113.6", "s1", "verify_ng", "/g", "", now.Add(5*time.Second))
	// .7: a loop two hours ago, outside the window.
	ins("203.0.113.7", "s1", "bv_pow_only", "/h", "", now.Add(-2*time.Hour))
	ins("203.0.113.7", "s1", "serve", "/h", "none", now.Add(-2*time.Hour+time.Second))
	ins("203.0.113.7", "s1", "verify_ng", "/h", "", now.Add(-2*time.Hour))
	// A challenge served to an address that never ran it: volume only.
	ins("198.51.100.9", "s1", "serve", "/", "none", now)
}

func checkStuck(t *testing.T, d *db.DB) {
	t.Helper()
	r, err := StuckVisitors(context.Background(), d, 60, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.Stuck != 2 || r.Rechallenged != 1 || r.VerifyFailed != 1 {
		t.Errorf("stuck %d (re-challenged %d, verify failed %d), want 2 (1, 1): %+v", r.Stuck, r.Rechallenged, r.VerifyFailed, r.Examples)
	}
	if r.Loaders != 10 || r.Passed != 5 {
		t.Errorf("loaders %d passed %d, want 10 and 5", r.Loaders, r.Passed)
	}
	if r.StuckShare() != 20 {
		t.Errorf("share %d%%, want 20%%", r.StuckShare())
	}
	if r.Serves != 7 || r.ServeIPs != 6 || r.Loads != 10 {
		t.Errorf("volume: serves %d to %d addresses, loads %d; want 7, 6, 10", r.Serves, r.ServeIPs, r.Loads)
	}
	// Most marks first; .1 and .6 have two each, so by address.
	if len(r.Examples) != 2 || r.Examples[0].IP != "203.0.113.1" || r.Examples[0].Rechallenged != 2 || r.Examples[0].Path != "/a" || r.Examples[0].Site != "s1" ||
		r.Examples[1].IP != "203.0.113.6" || r.Examples[1].VerifyFailed != 2 {
		t.Errorf("examples = %+v, want .1 (shown /a again twice) then .6 (2 failed)", r.Examples)
	}
	// Without the volume, the decision's figures are the same.
	q, err := StuckVisitors(context.Background(), d, 60, false)
	if err != nil {
		t.Fatal(err)
	}
	if q.Stuck != r.Stuck || q.Loaders != r.Loaders || q.Serves != 0 {
		t.Errorf("without volume: %+v", q)
	}
}

// StuckVisitors counts the addresses a challenge loop leaves behind -- a pass
// not honoured on the same page, an answer failing verification -- against
// those that ran the challenge, and tells them from everything that looks
// alike: a later challenge, another page, another site, a challenge served on
// purpose, a loop outside the window.  The breaker used to divide serves by
// addresses, and one scanner lifted that average past the threshold while
// everyone passed (2026-10-07).
func TestStuckVisitors(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	seedStuck(t, d)
	checkStuck(t, d)
}

// An empty window: nothing stuck, nothing to divide by.
func TestStuckVisitorsEmpty(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	r, err := StuckVisitors(context.Background(), d, 10, true)
	if err != nil || r.Stuck != 0 || r.Loaders != 0 || r.StuckShare() != 0 {
		t.Errorf("empty window = %+v (%v)", r, err)
	}
}
