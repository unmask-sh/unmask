package dashboard

import (
	"context"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// The landing page's 24h counters, read from the hourly rollup instead of the
// raw event table.
//
// The stats page moved to unmask_aggregate_hourly long ago; the landing page
// did not, and kept counting by scanning unmask_event on every load.  That is
// O(events in the window) against a table that only grows, and it stopped
// being viable exactly where it matters most: on the busiest fleet node the
// database had reached 9.4GB against 7GB of RAM, so nothing stayed cached and
// the page took 20 seconds cold (1.5s warm -- the same queries, once the pages
// were in memory).  Reading the rollup makes the cost O(hours), which is 24
// rows for a day and does not move as the install grows.
//
// The numbers themselves are unchanged: each function here has a Scan twin
// that is still used whenever the aggregate cannot answer -- a site or host
// filter (the rollup is install-wide), or an aggregator that has not finished
// its first pass.  The twins are the definition; these are the fast path.

// PhaseCount returns how many events of the given phases were recorded in the
// last `hours`.  Phases are OR-ed, mirroring the raw `phase IN (...)`.
func PhaseCount(ctx context.Context, d *db.DB, phases []string, site string, hosts []string, hours int) (int, bool) {
	if d == nil || len(phases) == 0 {
		return 0, false
	}
	if site != "" || len(hosts) > 0 || !HourlyAggReady() {
		return 0, false
	}
	return sumHourly(ctx, d, hkPhase, phases, hours)
}

// UnruledPoWCount returns how many ORDINARY visitors -- no rule pointing at
// them, on the transparent chain -- reached the given phase in the last
// `hours`.  The population of the abandon rate.
func UnruledPoWCount(ctx context.Context, d *db.DB, phase, site string, hosts []string, hours int) (int, bool) {
	if d == nil || phase == "" {
		return 0, false
	}
	if site != "" || len(hosts) > 0 || !HourlyAggReady() {
		return 0, false
	}
	return sumHourly(ctx, d, hkUnruledPoW, []string{phase}, hours)
}

// sumHourly totals one bucket kind over a set of keys within the window.
//
// Returns ok=false on any error rather than a zero: a landing-page KPI that
// silently reads zero because a query failed is indistinguishable from a quiet
// site, and the caller has a correct-but-slower path to fall back to.
func sumHourly(ctx context.Context, d *db.DB, kind string, keys []string, hours int) (int, bool) {
	ph := strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",")
	args := make([]any, 0, len(keys))
	for _, k := range keys {
		args = append(args, k)
	}
	var n int64
	err := d.QueryRowContext(ctx, `
        SELECT COALESCE(SUM(cnt), 0) FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+kind+`' AND `+hourWindow(ctx, hours, "bucket_hour")+`
          AND bucket_key IN (`+ph+`)`, args...).Scan(&n)
	if err != nil {
		return 0, false
	}
	return int(n), true
}
