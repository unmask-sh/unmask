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

	rows, err := FetchPaged(ctx, d, "", "", "", "", nil, 0, 100, 0)
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

