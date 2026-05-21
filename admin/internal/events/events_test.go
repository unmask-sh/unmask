package events

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

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

// TestNormalizeEventTimeLegacy confirms that pre-millisecond rows (the old
// DEFAULT CURRENT_TIMESTAMP format) still parse and still sort below newer
// millisecond rows of the same second.
func TestNormalizeEventTimeLegacy(t *testing.T) {
	cases := []struct {
		in      string
		display string
		tsMs    int64
	}{
		{"2026-05-20 22:00:54", "2026-05-20 22:00:54.000", 1779314454000},
		{"2026-05-20 22:00:54.712", "2026-05-20 22:00:54.712", 1779314454712},
		{"2026-05-20T22:00:54Z", "2026-05-20 22:00:54.000", 1779314454000},
	}
	for _, c := range cases {
		display, _, tsMs := normalizeEventTime(sql.NullTime{}, sql.NullString{String: c.in, Valid: true})
		if display != c.display || tsMs != c.tsMs {
			t.Errorf("normalizeEventTime(%q) = (%q, %d), want (%q, %d)",
				c.in, display, tsMs, c.display, c.tsMs)
		}
	}
}
