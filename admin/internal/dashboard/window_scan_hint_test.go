package dashboard

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The two raw window scans the sub-day stats ranges run (and the 24h ones
// until the hourly rollup is ready) had no index pin.  Without planner
// statistics -- the state of every large install -- SQLite walked the whole
// verdict index for a one-hour window (369 MB, 17-23 s cold on 8M rows).  The
// pin seeks the date index; a site or host predicate keeps its own index.
func TestWindowScansPinTheDateIndex(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		if _, err := d.Exec(`INSERT INTO unmask_event (site, host, ip_address, ja4_verdict, phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
		                      VALUES ('default', 'default', X'0a000001', ?, 'serve', 0, 0, '', '', '{}', ?)`,
			[]string{"bot_scanner", "h1_lax", "(none)"}[i%3], time.Now().UTC().Add(-time.Minute).Format("2006-01-02 15:04:05")); err != nil {
			t.Fatal(err)
		}
	}
	since := tsWindow(ctx, 1, "date_created")
	explain := func(stmt string) string {
		rows, err := d.QueryContext(ctx, "EXPLAIN QUERY PLAN "+stmt)
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
	for name, sql := range map[string]string{
		"funnel":  funnelScanSQL(eventWindowHint(d, since, ""), since, ""),
		"verdict": verdictDistScanSQL(eventWindowHint(d, since, ""), since, ""),
	} {
		plan := explain(sql)
		if !strings.Contains(plan, "idx_unmask_event_date") {
			t.Errorf("%s scan must seek the date index; plan:\n%s", name, plan)
		}
		if strings.Contains(plan, "SCAN") && strings.Contains(plan, "idx_unmask_event_verdict") {
			t.Errorf("%s scan walks the verdict index end to end; plan:\n%s", name, plan)
		}
	}
	// A site predicate: no pin, so the planner may use the site index.
	if h := eventWindowHint(d, since, siteCond("news.example.com")); h != "" {
		t.Errorf("a site-filtered scan must not be pinned to the date index, got %q", h)
	}
	// The pin must not change the answer.
	rows, err := VerdictDistribution(ctx, d, "", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, r := range rows {
		total += r.Count
	}
	if total != 12 {
		t.Errorf("verdict distribution over the window: want 12 events, got %d (%+v)", total, rows)
	}
	fun, err := Funnel(ctx, d, "", nil, 1, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(fun) == 0 {
		t.Error("funnel over the window returned no rows")
	}
}
