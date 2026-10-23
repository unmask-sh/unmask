package dashboard

import (
	"context"
	"strings"
	"testing"
	"time"
)

// explainPlan joins the planner's detail lines for one statement.
func explainPlan(ctx context.Context, t *testing.T, q func(context.Context, string, ...any) (rowsScanner, error), stmt string, args ...any) string {
	t.Helper()
	rows, err := q(ctx, "EXPLAIN QUERY PLAN "+stmt, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("explain scan: %v", err)
		}
		sb.WriteString(detail)
		sb.WriteString(" | ")
	}
	return sb.String()
}

// TestCookieMinuteTailReadsTheKeyRange: the request-count card's read of the
// unsettled minutes is bounded on both ends, and so goes through the primary
// key.  The test database has no planner statistics, like a large install:
// there the open-ended shape was planned as a walk of the whole table through
// the kind index (logged for the record, not asserted -- it is the planner's
// choice, and a future SQLite may choose better).
func TestCookieMinuteTailReadsTheKeyRange(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	now := time.Now().Unix() / 60
	for i := int64(0); i < 30; i++ {
		for _, site := range []string{"a.example", "b.example"} {
			for _, kind := range []string{"total", "pow", "challenge_served"} {
				if _, err := d.ExecContext(ctx, `INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?, ?, ?, 1)`, now-i, site, kind); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	q := func(ctx context.Context, stmt string, args ...any) (rowsScanner, error) {
		return d.QueryContext(ctx, stmt, args...)
	}
	for _, site := range []string{"", "a.example"} {
		stmt, args := cookieMinutesStmt(now-180, now+cookieMinuteTailSlack, site)
		plan := explainPlan(ctx, t, q, stmt, args...)
		if strings.Contains(plan, "SCAN") {
			t.Fatalf("site=%q: the bounded tail read is a scan: %s", site, plan)
		}
		if !strings.Contains(plan, "bucket_min>") {
			t.Fatalf("site=%q: the bounded tail read does not range over bucket_min: %s", site, plan)
		}
	}
	open, args := cookieMinutesStmt(now-180, 0, "")
	t.Logf("open-ended, for the record: %s", explainPlan(ctx, t, q, open, args...))
}

// TestReadAggregateStatusSeeksTheIdEnds: each end of the id range is its own
// statement, so each is one seek; together in one statement they were a walk
// of the whole covering index (the doctor's 2026-10-23 timeout).
func TestReadAggregateStatusSeeksTheIdEnds(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	q := func(ctx context.Context, stmt string, args ...any) (rowsScanner, error) {
		return d.QueryContext(ctx, stmt, args...)
	}
	for _, stmt := range []string{eventIDMinStmt, eventIDMaxStmt} {
		if plan := explainPlan(ctx, t, q, stmt); strings.Contains(plan, "SCAN") {
			t.Fatalf("%s: %s", stmt, plan)
		}
	}
	if plan := explainPlan(ctx, t, q, `SELECT MIN(id), MAX(id) FROM unmask_event`); !strings.Contains(plan, "SCAN") {
		t.Logf("the one-statement form is no longer a scan on this SQLite: %s", plan)
	}
}
