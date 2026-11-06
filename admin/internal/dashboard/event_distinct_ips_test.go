package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The gauge /metrics exports as unmask_event_unique_ip is the union of the
// per-verdict sketches of the window: every event counts, whatever its
// phase and whether or not it has a verdict, an address seen under two
// verdicts or in two hours counts once, and what lies outside the window
// does not count.  And it declines -- rather than answer 0 -- until the
// rollup has completed a pass.
func TestEventDistinctIPsIsTheUnionOfTheWindowsSketches(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/u.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	add := func(at time.Time, ip []byte, phase string, verdict any) {
		t.Helper()
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site, host, ip_address, phase, ja4_verdict, flags, reload_count, date_created)
			VALUES ('a.example', 'h', ?, ?, ?, 0, 0, ?)`, ip, phase, verdict, at.Format("2006-01-02 15:04:05")); err != nil {
			t.Fatal(err)
		}
	}
	// 300 addresses inside the window, in different hours, phases and
	// verdicts; the first hundred appear again under another verdict and
	// hour.  Few enough for the sketch's linear counting, which is exact to
	// within a few.
	const inWindow = 300
	for i := 0; i < inWindow; i++ {
		ip := []byte{10, 1, byte(i / 256), byte(i % 256)}
		at := now.Add(-time.Duration(i%20) * time.Hour)
		switch i % 3 {
		case 0:
			add(at, ip, "serve", "bot_curl")
		case 1:
			add(at, ip, "load", nil) // no verdict
		default:
			add(at, ip, "bv_pow_only", "chrome")
		}
		if i < 100 {
			add(now.Add(-2*time.Hour), ip, "serve", "chrome")
		}
	}
	// 50 more that are three days old.
	for i := 0; i < 50; i++ {
		add(now.Add(-72*time.Hour), []byte{10, 2, 0, byte(i)}, "serve", "bot_curl")
	}

	defer hourlyReady.Store(false)
	hourlyReady.Store(false)
	if n, ok := EventDistinctIPs(ctx, d, 24); ok {
		t.Fatalf("answered %d before the rollup completed a pass", n)
	}
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	n, ok := EventDistinctIPs(ctx, d, 24)
	if !ok {
		t.Fatal("the rollup declined after a completed pass")
	}
	if n < inWindow-9 || n > inWindow+9 { // 3% of 300
		t.Errorf("%d distinct addresses in 24 hours, want about %d", n, inWindow)
	}
	// The wider window takes the old ones in.
	if n, ok := EventDistinctIPs(ctx, d, 24*7); !ok || n < inWindow+50-11 || n > inWindow+50+11 {
		t.Errorf("%d distinct addresses in 7 days (ok=%v), want about %d", n, ok, inWindow+50)
	}
	// No database: no answer.
	if _, ok := EventDistinctIPs(ctx, nil, 24); ok {
		t.Error("answered with no database")
	}
}

// A window with no event in it is zero addresses, and that is an answer.
func TestEventDistinctIPsOfAnEmptyWindowIsZero(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/e.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	defer hourlyReady.Store(false)
	if err := AggregateHourly(context.Background(), d, nil); err != nil {
		t.Fatal(err)
	}
	if n, ok := EventDistinctIPs(context.Background(), d, 24); !ok || n != 0 {
		t.Errorf("empty window: %d, ok=%v; want 0, true", n, ok)
	}
}
