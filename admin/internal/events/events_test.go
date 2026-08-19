package events

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestNormalizeEventTimeFractional locks in tolerance for any fractional-second
// precision on date_created.  A value with other than exactly 3 fractional
// digits used to fail every strict layout and fall through to ts=0, which made
// the hunt log show a raw UTC string (no operator TZ / no JST) for that row.
func TestNormalizeEventTimeFractional(t *testing.T) {
	// All of these denote the same instant 2026-06-04 02:12:02 UTC + fraction.
	cases := []struct {
		in     string
		wantTs int64 // unix seconds (fraction floored)
	}{
		{"2026-06-04 02:12:02.350", 1780539122}, // canonical 3-digit
		{"2026-06-04 02:12:02.35", 1780539122},  // 2-digit (= the reported bug)
		{"2026-06-04 02:12:02.3", 1780539122},   // 1-digit
		{"2026-06-04 02:12:02", 1780539122},     // none
		{"2026-06-04T02:12:02.35Z", 1780539122}, // ISO, 2-digit
		{"2026-06-04T02:12:02Z", 1780539122},    // ISO, none
	}
	for _, c := range cases {
		display, ts, tsMs := normalizeEventTime(sql.NullTime{}, sql.NullString{String: c.in, Valid: true})
		if ts != c.wantTs {
			t.Errorf("normalizeEventTime(%q): ts=%d, want %d (display=%q)", c.in, ts, c.wantTs, display)
		}
		if ts == 0 {
			t.Errorf("normalizeEventTime(%q): ts=0 -> would skip JS reformat (display=%q)", c.in, display)
		}
		if tsMs < c.wantTs*1000 {
			t.Errorf("normalizeEventTime(%q): tsMs=%d below floor", c.in, tsMs)
		}
	}
}

// TestOverBlockStats checks the circuit-breaker signal query: it counts only
// browser-grade phase='serve' events in the window and reports distinct client
// IPs, so the caller can derive serves-per-IP (the re-challenge loop ratio).
// Bot-class serves (empty UA, or a confirmed bot_* JA4 verdict) must not touch
// either figure -- a scanner swarm is not a visitor trapped in a loop, and its
// volume otherwise drowns the ratio (the 2026-07-04 false trip).
func TestOverBlockStats(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	ins := func(ip, phase, ua, verdict string, n int) {
		for i := 0; i < n; i++ {
			ev := &Event{IPPacked: PackIP(ip), Phase: phase, UserAgent: ua, JA4Verdict: verdict, OccurredAt: now}
			if err := Insert(ctx, d, ev); err != nil {
				t.Fatal(err)
			}
		}
	}
	const chrome = "Mozilla/5.0 Chrome/126"
	// 3 distinct browser-grade IPs served, 9 serve events total (.1 looped 5x,
	// .2 looped 3x).  suspect_* is browser-shaped and stays in the count.
	ins("10.0.0.1", "serve", chrome, "", 5)
	ins("10.0.0.2", "serve", chrome, "suspect_chrome_h1", 3)
	ins("10.0.0.3", "serve", chrome, "ok", 1)
	ins("10.0.0.4", "load", chrome, "", 4) // non-serve must be excluded from both counts
	// Bot-class serves: excluded from serves AND from the distinct-IP figure.
	ins("10.0.0.5", "serve", "", "", 7)               // no User-Agent
	ins("10.0.0.6", "serve", "curl/8", "bot_curl", 6) // confirmed-bot verdict

	serves, ips, loads, err := OverBlockStats(ctx, d, 60)
	if err != nil {
		t.Fatal(err)
	}
	// The loads are counted too -- they are what tells a trapped visitor from a
	// scanner that never runs the JS -- but they must not leak into the serve
	// or IP figures.
	if loads != 4 {
		t.Errorf("loads = %d, want 4", loads)
	}
	if serves != 9 {
		t.Errorf("serves = %d, want 9 (load events and bot-class serves must be excluded)", serves)
	}
	if ips != 3 {
		t.Errorf("distinct IPs = %d, want 3 (bot-class IPs must be excluded)", ips)
	}
}

// TestSubsecondOrdering guards the hunt-log ordering fix: events that share a
// wall-clock second must still come back in their true arrival order, driven
// by the millisecond date_created timestamp rather than insert order alone.
func TestSubsecondOrdering(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	base := time.Date(2026, 5, 20, 22, 0, 54, 0, time.UTC)
	// All three land in the same second; inserted in an order that is neither
	// the funnel order nor the chronological order.
	for _, ev := range []struct {
		phase string
		ms    int
	}{
		{"serve", 39}, {"bv_pow_only", 211}, {"load", 712},
	} {
		e := &Event{
			IPPacked:   PackIP("1.2.3.4"),
			Phase:      ev.phase,
			OccurredAt: base.Add(time.Duration(ev.ms) * time.Millisecond),
		}
		if err := Insert(ctx, d, e); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := FetchPaged(ctx, d, "", "", "", "", "", "", "", nil, 0, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	// FetchPaged returns newest first: .712, .211, .039.
	wantPhase := []string{"load", "bv_pow_only", "serve"}
	wantMs := []int64{712, 211, 39}
	for i, r := range rows {
		if r.Phase != wantPhase[i] {
			t.Errorf("row %d: phase = %q, want %q", i, r.Phase, wantPhase[i])
		}
		if r.TsMs%1000 != wantMs[i] {
			t.Errorf("row %d: ts_ms %%1000 = %d, want %d (date=%q)", i, r.TsMs%1000, wantMs[i], r.Date)
		}
	}
}
