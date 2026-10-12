package dashboard

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// ServeReasons counts the challenge and deny pages served over the last
// `hours` (every phase=serve event) by the reason that sent the visitor there:
// the landing page's detections-by-reason card.  The counts add up to the
// "challenge fired" tile beside it, broken down.
//
// Install-wide, with the aggregator caught up, it reads the hourly rollup
// (kind svr).  That kind accumulates from the release that added it, so for
// about a day after an upgrade it holds only part of the window; it is used
// only when it accounts for every serve the per-phase rollup counted over the
// same hours (both are written in the same fold, so they agree exactly once
// the window lies wholly past the upgrade).  Otherwise -- and with a site or
// host filter, which the rollup does not carry -- the raw scan answers, as it
// does for the tile.  ok=false when that fails too (a timeout): the card says
// so rather than showing a quiet day.
func ServeReasons(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (map[string]int, bool) {
	if d == nil {
		return nil, false
	}
	if site == "" && len(hosts) == 0 && HourlyAggReady() {
		if m, ok := serveReasonsRollup(ctx, d, hours); ok {
			return m, true
		}
	}
	m, err := serveReasonsScan(ctx, d, site, hosts, hours)
	if err != nil {
		log.Printf("serve reasons: %v", err)
		return nil, false
	}
	return m, true
}

// serveReasonsRollup reads kind svr and declines (ok=false) unless it covers
// every serve hkPhase counted in the same hours.
func serveReasonsRollup(ctx context.Context, d *db.DB, hours int) (map[string]int, bool) {
	rows, err := d.QueryContext(ctx, `
        SELECT bucket_key, COALESCE(SUM(cnt), 0) FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+hkServeReason+`' AND `+hourWindow(ctx, hours, "bucket_hour")+`
        GROUP BY bucket_key`)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	m := map[string]int{}
	total := 0
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, false
		}
		m[k] += int(n)
		total += int(n)
	}
	if rows.Err() != nil {
		return nil, false
	}
	serves, ok := sumHourly(ctx, d, hkPhase, []string{"serve"}, hours)
	if !ok || serves != total {
		return nil, false
	}
	return m, true
}

// serveReasonsScan is the definition the rollup must agree with.
func serveReasonsScan(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (map[string]int, error) {
	expr := jsonExtract(d, "payload_json", "$.force_reason")
	sc := siteCond(site) + hostCond(hosts)
	win := tsWindow(ctx, hours, "date_created")
	rows, err := d.QueryContext(ctx, fmt.Sprintf(`
        SELECT COALESCE(%s, ''), COUNT(*) FROM unmask_event%s
        WHERE %s%s AND phase = 'serve'
        GROUP BY 1`, expr, eventWindowHint(d, win, sc), win, sc))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		m[serveReasonKey(k)] += int(n)
	}
	return m, rows.Err()
}

var serveReasonRE = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// serveReasonKey keeps a reason as written when it has the shape every reason
// the daemon writes has, and folds anything else -- an empty or missing value,
// which only an event older than the field carries -- into "unknown".  No list
// to keep in step: a reason added later is counted under its own name, and the
// card shows the raw value until it has a label.
func serveReasonKey(fr string) string {
	if serveReasonRE.MatchString(fr) {
		return fr
	}
	return "unknown"
}
