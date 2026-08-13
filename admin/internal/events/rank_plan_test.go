package events

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// planOf returns EXPLAIN QUERY PLAN's detail column, joined.
func planOf(t *testing.T, d *db.DB, stmt string, args ...any) string {
	t.Helper()
	rows, err := d.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+stmt, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var a, b, c int
		var detail string
		if err := rows.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		sb.WriteString(detail + "\n")
	}
	return sb.String()
}

// TestRankByIPPinsDateIndex is a scale regression guard.
//
// unmask_event carries an (ip_address, date_created) index.  With no equality
// predicate on ip_address, SQLite prefers scanning that entire covering index
// (it then gets GROUP BY order for free) over seeking the date_created range --
// so `GROUP BY ip_address` costs O(all events), not O(events in the window).  On
// the tool1-us production DB (3.9M events) that measured 1.4s warm / 10.3s cold
// for a *one hour* window, and it did not get cheaper with a narrower window.
// ANALYZE does not rescue it: ip_address is too high-cardinality to skip-scan.
// The query must therefore be pinned to idx_unmask_event_date.
func TestRankByIPPinsDateIndex(t *testing.T) {
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
	for i := 0; i < 20; i++ {
		if err := Insert(ctx, d, &Event{
			IPPacked:   PackIP(fmt.Sprintf("10.0.0.%d", i%5)),
			Phase:      "serve",
			OccurredAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	win := dateCreatedWindow(ctx, d, 60)
	stmt := `SELECT ip_address, COUNT(*) AS c FROM unmask_event` + d.EventDateIndexHint(win) + `
	         WHERE ` + win + `
	         GROUP BY ip_address ORDER BY c DESC LIMIT ?`
	plan := planOf(t, d, stmt, 30)

	if !strings.Contains(plan, "idx_unmask_event_date") {
		t.Errorf("RankByIP must seek the date index; plan:\n%s", plan)
	}
	if strings.Contains(plan, "idx_unmask_event_ip_date") {
		t.Errorf("RankByIP must NOT scan the (ip_address, date_created) covering index "+
			"(cost would grow with the table, not the window); plan:\n%s", plan)
	}

	// The site filter must not cost the index.  It is an extra predicate on a
	// low-cardinality column, so the plan should still seek the date index and
	// filter rows -- not fall back to scanning the (ip_address, date_created)
	// covering index, which is what made this query slow in the first place.
	condStmt := `SELECT ip_address, COUNT(*) AS c FROM unmask_event` + d.EventDateIndexHint(win) + `
	         WHERE ` + win + ` AND site = ?
	         GROUP BY ip_address ORDER BY c DESC LIMIT ?`
	sitePlan := planOf(t, d, condStmt, "example.com", 30)
	if !strings.Contains(sitePlan, "idx_unmask_event_date") {
		t.Errorf("RankByIP with a site filter stopped seeking the date index; plan:\n%s", sitePlan)
	}
	if strings.Contains(sitePlan, "idx_unmask_event_ip_date") {
		t.Errorf("RankByIP with a site filter fell back to the covering index; plan:\n%s", sitePlan)
	}
	// The hint must not change the answer: 5 distinct IPs, 4 events each.
	got, err := RankByIP(ctx, d, 60, 30, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 ranked IPs, got %d (%v)", len(got), got)
	}
	for _, r := range got {
		if r.Count != 4 {
			t.Errorf("ip %s: want count 4, got %d", r.Key, r.Count)
		}
	}
}

// TestEventDateHintSkippedWithoutWindow: INDEXED BY makes SQLite reject a plan
// that cannot use the named index, so the hint must be omitted when the query
// carries no date_created constraint.
func TestEventDateHintSkippedWithoutWindow(t *testing.T) {
	d := &db.DB{Driver: db.DriverSQLite}
	if got := d.EventDateIndexHint(""); got != "" {
		t.Errorf("no window must yield no hint, got %q", got)
	}
	if got := d.EventDateIndexHint("date_created > 'x'"); got == "" {
		t.Error("a windowed query on sqlite must be pinned to the date index")
	}
}

// TestSampleIPForJA4PinsDateIndex: the other GROUP BY ip_address query shares the
// same trap (its ja4 predicate has no index, so the planner falls back to the ip
// covering index).
func TestSampleIPForJA4PinsDateIndex(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	win := dateCreatedWindow(ctx, d, 60)
	stmt := `SELECT ip_address FROM unmask_event` + d.EventDateIndexHint(win) + `
	         WHERE ` + win + `
	           AND COALESCE(ja4, '') = ?
	           AND COALESCE(ip_address, '') <> ''
	         GROUP BY ip_address ORDER BY COUNT(*) DESC LIMIT 1`
	plan := planOf(t, d, stmt, "t13d")
	if !strings.Contains(plan, "idx_unmask_event_date") {
		t.Errorf("SampleIPForJA4 must seek the date index; plan:\n%s", plan)
	}
	if strings.Contains(plan, "idx_unmask_event_ip_date") {
		t.Errorf("SampleIPForJA4 must NOT scan the ip covering index; plan:\n%s", plan)
	}
}
