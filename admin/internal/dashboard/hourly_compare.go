package dashboard

import (
	"context"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// HourlyCompare is the dashboard's "requests per hour, today against
// yesterday" chart: two days of hourly request totals in the operator's zone.
type HourlyCompare struct {
	Today     [24]int
	Yesterday [24]int
	// NowHour is the hour (0-23, operator's zone) the reading was taken in;
	// today's bars after it hold nothing yet.
	NowHour int
	// OK is false when the counters hold nothing for either day -- the
	// access-log feed is off, or the install is younger than an hour.
	OK bool
}

// HourlyRequests reads two days of unmask_cookie_minute 'total' rows -- the
// same counter the composition card divides up, so the two agree -- and sums
// them per hour of the operator's calendar day.  site "" is every site.
//
// Minute rows rather than the hourly rollup: the rollup settles two hours
// behind, and the chart's point is the current hour against the same hour
// yesterday.  Two days is at most 48 hours of minute rows per site, read by
// the table's (kind, bucket_min) index.
func HourlyRequests(ctx context.Context, d *db.DB, site string, loc *time.Location, now time.Time) (HourlyCompare, error) {
	var hc HourlyCompare
	if d == nil {
		return hc, nil
	}
	if loc == nil {
		loc = time.UTC
	}
	local := now.In(loc)
	hc.NowHour = local.Hour()
	today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	yesterday := today.AddDate(0, 0, -1)
	args := []any{yesterday.Unix() / 60}
	cond := ""
	if site != "" {
		cond = " AND site = ?"
		args = append(args, site)
	}
	rows, err := d.QueryContext(ctx, `
        SELECT bucket_min, SUM(cnt)
        FROM unmask_cookie_minute
        WHERE kind = 'total' AND bucket_min >= ?`+cond+`
        GROUP BY bucket_min`, args...)
	if err != nil {
		return HourlyCompare{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var min int64
		var n int
		if err := rows.Scan(&min, &n); err != nil {
			return HourlyCompare{}, err
		}
		t := time.Unix(min*60, 0).In(loc)
		switch {
		case t.Before(today):
			hc.Yesterday[t.Hour()] += n
		default:
			hc.Today[t.Hour()] += n
		}
		hc.OK = true
	}
	return hc, rows.Err()
}
