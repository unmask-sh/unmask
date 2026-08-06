package events

import (
	"context"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// RebindLineageRow: one solved challenge (a _bvj lineage) and how far it has
// travelled.
//
// A lineage is minted by one solve and can then be re-bound onto other
// addresses without solving again.  That is a feature for a phone leaving
// wifi, and the whole business model of a distributed crawler: solve once,
// then walk the credential across a fleet.  The two look identical in every
// per-request view -- each individual request is a legitimate pass -- and
// differ only in this aggregate: how many distinct addresses one solve has
// been carried to.
//
// Measured on a production install, the crawler that prompted this had solved
// once and re-bound across 419 addresses, and nothing in the interface could
// say so.
type RebindLineageRow struct {
	Lineage  string // random id from the _bvj cookie
	IPs      int    // distinct addresses this solve has been re-bound onto (in the window)
	Rebinds  int    // successful silent re-binds (in the window)
	Rejects  int    // refused re-binds -- cap, ASN veto, UA/JA4 mismatch (in the window)
	LastSeen string // most recent activity, as stored (UTC)
}

// jsonField renders a payload_json field read for the active driver.  SQLite's
// json_extract returns the bare value; MariaDB's needs unquoting or every
// comparison carries the quotes.
func jsonField(d *db.DB, field string) string {
	if d.Driver != "sqlite" {
		return `JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.` + field + `'))`
	}
	return `json_extract(payload_json, '$.` + field + `')`
}

// RankByRebindLineage ranks lineages by how many distinct addresses they have
// been re-bound onto, then by volume.
//
// Ordered by address count rather than by request count on purpose: a busy
// phone can re-bind often between two networks and is uninteresting, while a
// credential appearing on many addresses is the shape worth looking at even at
// low volume -- the production case ran at a handful of requests per five
// minutes and was invisible in every volume ranking on the page.
//
// Rejects are counted beside the successes because they say the cap is
// biting: a lineage with far more refusals than passes is one the operator's
// limits are already holding back, and one with none has never come close.
func RankByRebindLineage(ctx context.Context, d *db.DB, sinceMin, limit int) ([]RebindLineageRow, error) {
	if d == nil {
		return nil, nil
	}
	if limit < 1 || limit > 200 {
		limit = 20
	}
	win := dateCreatedWindow(ctx, d, sinceMin)
	if win == "" {
		win = "1=1"
	}
	lineage := jsonField(d, "lineage")
	stmt := `SELECT ` + lineage + ` AS lin,
	                COUNT(DISTINCT CASE WHEN phase = ? THEN ip_address END),
	                SUM(CASE WHEN phase = ? THEN 1 ELSE 0 END),
	                SUM(CASE WHEN phase = ? THEN 1 ELSE 0 END),
	                MAX(date_created)
	         FROM unmask_event
	         WHERE ` + win + ` AND phase IN (?, ?) AND ` + lineage + ` IS NOT NULL AND ` + lineage + ` <> ''
	         GROUP BY lin
	         ORDER BY 2 DESC, 3 DESC
	         LIMIT ?`
	rows, err := d.QueryContext(ctx, stmt,
		string(PhaseBVRebind), string(PhaseBVRebind), string(PhaseBVRebindReject),
		string(PhaseBVRebind), string(PhaseBVRebindReject), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RebindLineageRow{}
	for rows.Next() {
		var r RebindLineageRow
		var last any
		if err := rows.Scan(&r.Lineage, &r.IPs, &r.Rebinds, &r.Rejects, &last); err != nil {
			return nil, err
		}
		r.LastSeen = scanTimeString(last)
		// A lineage that only ever produced refusals never re-bound anywhere,
		// and listing it as travel would overstate what happened.
		if r.Rebinds == 0 {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// scanTimeString normalizes MAX(date_created), which arrives as a string on
// SQLite and as time.Time on MariaDB.
func scanTimeString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case interface{ Format(string) string }:
		return t.Format("2006-01-02 15:04:05")
	}
	return ""
}

// RebindLineageCaps reports, per lineage, the counters the cap is enforced
// against: total re-binds ever, and re-binds inside the current window.  These
// live outside the event log (the cap has to survive retention pruning), so
// they are read separately and merged by the caller.
//
// Returns an empty map rather than an error when the table is absent -- an
// install that has never had a roaming client has no rows, and a missing cap
// reading must not blank the ranking beside it.
func RebindLineageCaps(ctx context.Context, d *db.DB, lineages []string) map[string][2]int {
	out := map[string][2]int{}
	if d == nil || len(lineages) == 0 {
		return out
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(lineages)), ",")
	args := make([]any, 0, len(lineages))
	for _, l := range lineages {
		args = append(args, l)
	}
	rows, err := d.QueryContext(ctx,
		"SELECT lineage, `count`, window_count FROM unmask_rebind_lineage "+
			"WHERE lineage IN ("+ph+")", args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var l string
		var total, window int
		if err := rows.Scan(&l, &total, &window); err != nil {
			return out
		}
		out[l] = [2]int{total, window}
	}
	return out
}
