package dashboard

import (
	"context"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// The Ask AI tool events_count, answered from the hourly rollup where the
// question has no filter the rollup lacks: every event of the window by hour
// and phase, and the distinct addresses as the union of the per-site sketches
// (hkSiteIP, which every event feeds, its site being "default" when none is
// set).  The raw table is then not read at all, which on an install whose
// database is larger than its memory is the difference between an answer in
// milliseconds and a scan of minutes (2026-10-18).
//
// Like PhaseCount these are the fast path, not the definition: the counts
// are those of CountHourly over the same hours, and the addresses an
// estimate within a couple of percent.  The rollup is folded every minute
// (AggregateHourly), so it may lack the newest minute; the caller says so.

// PhasesByHour returns, for each hour of the window that has events, the
// events by phase, keyed by the rollup's 'YYYY-MM-DD HH' (UTC).  ok is false
// when the rollup cannot answer (no full pass yet, or a read error).
func PhasesByHour(ctx context.Context, d *db.DB, hours int) (map[string]map[string]int, bool) {
	if d == nil || !HourlyAggReady() {
		return nil, false
	}
	rows, err := d.QueryContext(ctx, `
        SELECT bucket_hour, bucket_key, cnt FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+hkPhase+`' AND `+hourWindow(ctx, hours, "bucket_hour"))
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var hour, phase string
		var n int64
		if err := rows.Scan(&hour, &phase, &n); err != nil {
			return nil, false
		}
		if out[hour] == nil {
			out[hour] = map[string]int{}
		}
		out[hour][phase] += int(n)
	}
	if rows.Err() != nil {
		return nil, false
	}
	return out, true
}

// DistinctIPsByHour estimates the distinct addresses of the window, per hour
// (keyed as PhasesByHour) and over the whole window, from the per-site
// sketches.  ok is false when the rollup cannot answer.
func DistinctIPsByHour(ctx context.Context, d *db.DB, hours int) (map[string]int, int, bool) {
	if d == nil || !HourlyAggReady() {
		return nil, 0, false
	}
	rows, err := d.QueryContext(ctx, `
        SELECT bucket, sketch FROM unmask_aggregate_hll
        WHERE bucket_kind = '`+hkSiteIP+`' AND `+hourWindow(ctx, hours, "bucket"))
	if err != nil {
		return nil, 0, false
	}
	defer rows.Close()
	byHour := map[string]*hll{}
	all := &hll{}
	for rows.Next() {
		var hour string
		var blob []byte
		if err := rows.Scan(&hour, &blob); err != nil {
			return nil, 0, false
		}
		s := byHour[hour]
		if s == nil {
			s = &hll{}
			byHour[hour] = s
		}
		s.mergeBytes(blob)
		all.mergeBytes(blob)
	}
	if rows.Err() != nil {
		return nil, 0, false
	}
	out := make(map[string]int, len(byHour))
	for hour, s := range byHour {
		out[hour] = s.estimate()
	}
	total := 0
	if len(byHour) > 0 {
		total = all.estimate()
	}
	return out, total, true
}
