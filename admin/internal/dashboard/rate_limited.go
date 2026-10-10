package dashboard

import (
	"context"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// RateLimitedServes counts the challenge pages served on the rate-limit path
// (phase=serve, payload rl=1) in the last hours, for the dashboard's pipeline.
// It reads the hkServeRL rollup, which is install-wide: with a site or host
// filter, or before the rollup's first pass, known is false and the pipeline
// shows the stage without a figure rather than scanning the event table for
// a number the page redraws every minute.
func RateLimitedServes(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (n int, known bool, err error) {
	if d == nil || site != "" || len(hosts) > 0 || !HourlyAggReady() {
		return 0, false, nil
	}
	var total int64
	err = d.QueryRowContext(ctx, `
        SELECT COALESCE(SUM(cnt), 0) FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+hkServeRL+`' AND `+hourWindow(ctx, hours, "bucket_hour")).Scan(&total)
	if err != nil {
		return 0, false, err
	}
	return int(total), true, nil
}
