package events

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// HourCount is one hour of Counts: when the hour starts in the caller's
// zone, its events by phase, and the distinct addresses seen in it.
type HourCount struct {
	Hour        string         `json:"hour"`
	Phases      map[string]int `json:"phases"`
	DistinctIPs int            `json:"distinct_ips"`
}

// Counts is a window of the event log counted rather than read: every event
// the filters match, by phase, the distinct addresses among them, and the
// same split hour by hour.  Hours with nothing in them are left out.
type Counts struct {
	Total       int            `json:"total"`
	DistinctIPs int            `json:"distinct_ips"`
	Phases      map[string]int `json:"phases"`
	Hours       []HourCount    `json:"hours"`
}

// hourColExpr buckets date_created to its UTC hour, 'YYYY-MM-DD HH'.  Rows
// are stored in UTC on both engines (the dashboard's hourly rollup relies on
// the same), and the caller's zone is applied to the label in Go.
func hourColExpr(d *db.DB) string {
	if d.Driver == db.DriverSQLite {
		return "strftime('%Y-%m-%d %H', date_created)"
	}
	return "DATE_FORMAT(date_created, '%Y-%m-%d %H')"
}

// CountHourly counts the window under the hunt's filters -- the ones
// FetchPaged pages by, so the count and a page of rows describe the same
// set.  A question of "how many" over a window is answered here by the
// database in full; a page of rows is the newest few, and whoever reads it
// cannot count what it left out.  Three scans of the window (phase by hour,
// addresses by hour, addresses overall), each pinned to the date index as the
// hunt's rankings are, with the same degradation when the index is missing.
func CountHourly(ctx context.Context, d *db.DB, ipSubstr, ja4Substr, uaSubstr, phase, forceReason, site string, hosts []string, sinceMin int, loc *time.Location) (Counts, error) {
	if loc == nil {
		loc = time.UTC
	}
	where, args, win := filterClause(ctx, d, ipSubstr, ja4Substr, uaSubstr, "", phase, forceReason, site, hosts, sinceMin)
	hint := ""
	if win != "" {
		hint = d.EventDateIndexHint(win)
	}
	query := func(sel, group string) (*sql.Rows, error) {
		run := func(h string) (*sql.Rows, error) {
			return d.QueryContext(ctx, "SELECT "+sel+" FROM unmask_event"+h+" WHERE "+where+group, args...)
		}
		rows, err := run(hint)
		if err != nil && hint != "" && strings.Contains(err.Error(), "idx_unmask_event_date") {
			rows, err = run("") // the missing-index degradation of RankServes
		}
		return rows, err
	}
	label := func(key string) string {
		t, err := time.ParseInLocation("2006-01-02 15", key, time.UTC)
		if err != nil {
			return key
		}
		return t.In(loc).Format(time.RFC3339)
	}
	out := Counts{Phases: map[string]int{}, Hours: []HourCount{}}
	byHour := map[string]*HourCount{}
	hourOf := func(key string) *HourCount {
		hc := byHour[key]
		if hc == nil {
			hc = &HourCount{Hour: label(key), Phases: map[string]int{}}
			byHour[key] = hc
		}
		return hc
	}

	hour := hourColExpr(d)
	rows, err := query(hour+" AS h, phase, COUNT(*)", " GROUP BY h, phase")
	if err != nil {
		return Counts{}, err
	}
	for rows.Next() {
		var h, p string
		var n int
		if err := rows.Scan(&h, &p, &n); err != nil {
			rows.Close()
			return Counts{}, err
		}
		hourOf(h).Phases[p] += n
		out.Phases[p] += n
		out.Total += n
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Counts{}, err
	}
	rows.Close()

	rows, err = query(hour+" AS h, COUNT(DISTINCT ip_address)", " GROUP BY h")
	if err != nil {
		return Counts{}, err
	}
	for rows.Next() {
		var h string
		var n int
		if err := rows.Scan(&h, &n); err != nil {
			rows.Close()
			return Counts{}, err
		}
		hourOf(h).DistinctIPs = n
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Counts{}, err
	}
	rows.Close()

	rows, err = query("COUNT(DISTINCT ip_address)", "")
	if err != nil {
		return Counts{}, err
	}
	if rows.Next() {
		if err := rows.Scan(&out.DistinctIPs); err != nil {
			rows.Close()
			return Counts{}, err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Counts{}, err
	}
	rows.Close()

	keys := make([]string, 0, len(byHour))
	for k := range byHour {
		keys = append(keys, k)
	}
	sort.Strings(keys) // the key is UTC, so its order is time's
	for _, k := range keys {
		out.Hours = append(out.Hours, *byHour[k])
	}
	return out, nil
}
