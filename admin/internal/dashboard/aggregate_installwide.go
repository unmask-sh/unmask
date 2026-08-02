package dashboard

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// installWideState is the unmask_aggregate_state.name whose last_id holds the
// last settled UTC unix-hour folded into the install-wide (unfiltered-view)
// hourly aggregates: hkTrafficIPAll (unmask_aggregate_hll) and hkCookiePass
// (unmask_aggregate_hourly).
//
// It intentionally keeps its OWN cursor rather than sharing trafficIPState. On
// upgrade the per-site traffic cursor is already advanced past the retained
// history, so piggy-backing on it would leave the new install-wide buckets
// empty for the whole 30-day window until time caught up. A fresh cursor here
// backfills the retained window on the first run after the feature ships.
const installWideState = "iw_hourly"

// RollupInstallWideHourly folds the per-minute nginx-log tables
// (unmask_traffic_hll kind='ip', unmask_cookie_minute) into install-wide hourly
// aggregates for the default (site="" / unfiltered) stats view:
//
//   - unmask_aggregate_hll(bucket_kind=hkTrafficIPAll, bucket_key=”) — the hour's
//     distinct-IP HLL sketch unioned across every site.  DailyUniqueIPs then merges
//     ~720 hourly sketches instead of the ~35k per-site sketches (~33 MB) the
//     unfiltered read was pulling.
//   - unmask_aggregate_hourly(bucket_kind=hkCookiePass, bucket_key='<cookie kind>')
//     — the hour's pass counts summed across every site.  DailyPassByDay then reads
//     ~720 hourly rows instead of scanning ~333k per-minute, per-site rows.
//
// Both preserve hour resolution, so the read side still folds hours into the
// operator's cookie-TZ day (day boundaries follow the operator — CLAUDE.md #6);
// a daily rollup could not, because an HLL sketch cannot be re-split once
// unioned and a summed count cannot be re-split once merged.
//
// Same settle / batch / idempotency contract as RollupTrafficHLL: it re-folds
// each hour from scratch and overwrites, advances the cursor only after a batch
// commits, and keeps the most recent trafficSettleHours out of the rollup so a
// late nginx-log flush of a past minute settles first. The current, unsettled
// hours are read live from the per-minute tables by the cards, so they never
// lag. Driven by the admin's 60s ticker plus a startup run. gip is not needed
// (country dimension is handled elsewhere).
func RollupInstallWideHourly(ctx context.Context, d *db.DB) error {
	if d == nil {
		return nil
	}
	cursor, err := stateCursor(ctx, d, installWideState)
	if err != nil {
		return err
	}
	nowHour := time.Now().Unix() / 3600
	lastSettled := nowHour - trafficSettleHours
	// Never reach back before the retention window: the per-minute rows are
	// pruned at hourlyKeep days, so older hours have nothing left to fold.
	floor := nowHour - int64(hourlyKeep)*24
	start := cursor + 1
	if start < floor {
		start = floor
	}
	for start <= lastSettled {
		end := start + trafficRollupBatchHours - 1
		if end > lastSettled {
			end = lastSettled
		}
		if err := rollupInstallWideRange(ctx, d, start, end); err != nil {
			return err
		}
		start = end + 1
	}
	return nil
}

// rollupInstallWideRange folds UTC unix-hours [fromHour, toHour] (inclusive)
// into the install-wide sketch (one per hour) and cookie counts (one per
// hour × kind), then advances the cursor to toHour, all in a single tx.
func rollupInstallWideRange(ctx context.Context, d *db.DB, fromHour, toHour int64) error {
	// 1) install-wide distinct-IP sketch per hour = union of all sites' minute
	//    sketches for that hour.
	ipByHour, err := installWideIPSketches(ctx, d, fromHour, toHour)
	if err != nil {
		return err
	}
	// 2) install-wide cookie-pass counts per (hour, kind) = sum across sites.
	ckByHourKind, err := installWideCookieCounts(ctx, d, fromHour, toHour)
	if err != nil {
		return err
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	sqlite := d.Driver == db.DriverSQLite

	// HLL sketches: recompute-and-overwrite (idempotent — the range is re-folded
	// from scratch, so a replayed batch must not stack onto a stored sketch).
	upHLL := `INSERT INTO unmask_aggregate_hll (bucket, bucket_kind, bucket_key, sketch) VALUES (?, ?, ?, ?)`
	if sqlite {
		upHLL += ` ON CONFLICT(bucket, bucket_kind, bucket_key) DO UPDATE SET sketch = excluded.sketch`
	} else {
		upHLL += ` ON DUPLICATE KEY UPDATE sketch = VALUES(sketch)`
	}
	hstmt, err := tx.PrepareContext(ctx, upHLL)
	if err != nil {
		return err
	}
	defer hstmt.Close()
	for h, s := range ipByHour {
		bucket := time.Unix(h*3600, 0).UTC().Format("2006-01-02 15")
		if _, err := hstmt.ExecContext(ctx, bucket, hkTrafficIPAll, "", s[:]); err != nil {
			return err
		}
	}

	// Counts: recompute-and-overwrite (SET cnt = excluded.cnt, NOT cnt + …), for
	// the same replay-safety reason as the sketches above.
	upCnt := `INSERT INTO unmask_aggregate_hourly (bucket_hour, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, ?)`
	if sqlite {
		upCnt += ` ON CONFLICT(bucket_hour, bucket_kind, bucket_key) DO UPDATE SET cnt = excluded.cnt`
	} else {
		upCnt += ` ON DUPLICATE KEY UPDATE cnt = VALUES(cnt)`
	}
	cstmt, err := tx.PrepareContext(ctx, upCnt)
	if err != nil {
		return err
	}
	defer cstmt.Close()
	for k, c := range ckByHourKind {
		bucket := time.Unix(k.hour*3600, 0).UTC().Format("2006-01-02 15")
		if _, err := cstmt.ExecContext(ctx, bucket, hkCookiePass, k.kind, c); err != nil {
			return err
		}
	}

	// Advance the cursor to toHour even when the range had no rows (a quiet
	// window is still "done"); not advancing would rescan it every pass.
	st := `INSERT INTO unmask_aggregate_state (name, last_id, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`
	if sqlite {
		st += ` ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id, updated_at = excluded.updated_at`
	} else {
		st += ` ON DUPLICATE KEY UPDATE last_id = VALUES(last_id), updated_at = VALUES(updated_at)`
	}
	if _, err := tx.ExecContext(ctx, st, installWideState, toHour); err != nil {
		return err
	}
	return tx.Commit()
}

// installWideIPSketches unions every site's per-minute IP sketch in
// [fromHour, toHour] into one sketch per UTC unix-hour.
func installWideIPSketches(ctx context.Context, d *db.DB, fromHour, toHour int64) (map[int64]*hll, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT bucket_min, sketch FROM unmask_traffic_hll
		 WHERE kind = 'ip' AND bucket_min >= ? AND bucket_min < ?`,
		fromHour*60, (toHour+1)*60)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byHour := map[int64]*hll{}
	for rows.Next() {
		var bm int64
		var blob []byte
		if err := rows.Scan(&bm, &blob); err != nil {
			return nil, err
		}
		h := bm / 60
		s := byHour[h]
		if s == nil {
			s = &hll{}
			byHour[h] = s
		}
		s.mergeBytes(blob)
	}
	return byHour, rows.Err()
}

type hourKindKey struct {
	hour int64
	kind string
}

// installWideCookieCounts sums every site's per-minute pass counts in
// [fromHour, toHour] into one count per (UTC unix-hour, kind).
func installWideCookieCounts(ctx context.Context, d *db.DB, fromHour, toHour int64) (map[hourKindKey]int64, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT bucket_min, kind, cnt FROM unmask_cookie_minute
		 WHERE bucket_min >= ? AND bucket_min < ?`,
		fromHour*60, (toHour+1)*60)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[hourKindKey]int64{}
	for rows.Next() {
		var bm, cnt int64
		var kind string
		if err := rows.Scan(&bm, &kind, &cnt); err != nil {
			return nil, err
		}
		by[hourKindKey{bm / 60, kind}] += cnt
	}
	return by, rows.Err()
}

// installWideCountryState is the cursor for the install-wide per-country pass
// counts (hkCountryPass).  It is separate from installWideState because its
// source is the already-hourly unmask_traffic_country_hourly table (not the
// per-minute tables), so it backfills independently — and so that adding it did
// not disturb the already-advanced installWideState cursor of the first rollup.
const installWideCountryState = "iw_country"

// RollupInstallWideCountry folds the (already-hourly, per-site)
// unmask_traffic_country_hourly table into install-wide per-(hour, country, kind)
// counts in unmask_aggregate_hourly(bucket_kind=hkCountryPass), summed across
// sites, so DailyPassByCountry's default view reads install-wide hourly rows
// instead of the ~300-site country fan-out.  Same settle / batch / idempotency
// contract as RollupInstallWideHourly, on its own cursor.  Driven by the 60s
// ticker.
func RollupInstallWideCountry(ctx context.Context, d *db.DB) error {
	if d == nil {
		return nil
	}
	cursor, err := stateCursor(ctx, d, installWideCountryState)
	if err != nil {
		return err
	}
	nowHour := time.Now().Unix() / 3600
	lastSettled := nowHour - trafficSettleHours
	floor := nowHour - int64(hourlyKeep)*24
	start := cursor + 1
	if start < floor {
		start = floor
	}
	for start <= lastSettled {
		end := start + trafficRollupBatchHours - 1
		if end > lastSettled {
			end = lastSettled
		}
		if err := rollupInstallWideCountryRange(ctx, d, start, end); err != nil {
			return err
		}
		start = end + 1
	}
	return nil
}

type countryHourKey struct {
	hour    int64
	country string
	kind    string
}

// rollupInstallWideCountryRange sums per-site country counts in unix-hours
// [fromHour, toHour] into one count per (hour, country, kind) and advances the
// cursor to toHour, all in a single tx.  The GROUP BY already collapses sites;
// the map only materializes the rows so the read cursor is closed before the
// write tx opens.
func rollupInstallWideCountryRange(ctx context.Context, d *db.DB, fromHour, toHour int64) error {
	rows, err := d.QueryContext(ctx,
		`SELECT bucket_hour, country, kind, SUM(cnt) FROM unmask_traffic_country_hourly
		 WHERE bucket_hour >= ? AND bucket_hour <= ?
		 GROUP BY bucket_hour, country, kind`, fromHour, toHour)
	if err != nil {
		return err
	}
	agg := map[countryHourKey]int64{}
	for rows.Next() {
		var bh, cnt int64
		var country sql.NullString
		var kind string
		if err := rows.Scan(&bh, &country, &kind, &cnt); err != nil {
			rows.Close()
			return err
		}
		agg[countryHourKey{bh, country.String, kind}] += cnt
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	sqlite := d.Driver == db.DriverSQLite
	upCnt := `INSERT INTO unmask_aggregate_hourly (bucket_hour, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, ?)`
	if sqlite {
		upCnt += ` ON CONFLICT(bucket_hour, bucket_kind, bucket_key) DO UPDATE SET cnt = excluded.cnt`
	} else {
		upCnt += ` ON DUPLICATE KEY UPDATE cnt = VALUES(cnt)`
	}
	stmt, err := tx.PrepareContext(ctx, upCnt)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, c := range agg {
		bucket := time.Unix(k.hour*3600, 0).UTC().Format("2006-01-02 15")
		// key = '<country>|<kind>'; country is a 2-letter ISO code or '' (unresolved),
		// kind is a fixed token — neither contains '|', so SplitN(…,2) is exact.
		if _, err := stmt.ExecContext(ctx, bucket, hkCountryPass, k.country+"|"+k.kind, c); err != nil {
			return err
		}
	}
	st := `INSERT INTO unmask_aggregate_state (name, last_id, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`
	if sqlite {
		st += ` ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id, updated_at = excluded.updated_at`
	} else {
		st += ` ON DUPLICATE KEY UPDATE last_id = VALUES(last_id), updated_at = VALUES(updated_at)`
	}
	if _, err := tx.ExecContext(ctx, st, installWideCountryState, toHour); err != nil {
		return err
	}
	return tx.Commit()
}

// installWideBlockedState is the cursor for the install-wide 'ipc'/'ipp'/'ipb'
// distinct-IP sketches (hkTrafficBlockedAll) feeding the overview's non-human-%
// card.  Own cursor so it backfills the retained window on first run without
// disturbing installWideState (which DailyUniqueIPs / DailyPassByDay read).
const installWideBlockedState = "iw_blocked"

// RollupInstallWideBlocked unions every site's per-minute 'ipc' (challenged),
// 'ipp' (passed) and 'ipb' (listed crawler passed without a challenge) sketches
// into one install-wide sketch per (hour, kind) in
// unmask_aggregate_hll(bucket_kind=hkTrafficBlockedAll, bucket_key='ipc'|'ipp'|'ipb'),
// so the overview's non-human-% default view merges ~48 hourly sketches instead
// of the ~8k per-site rows.  ('ip'/total reuses hkTrafficIPAll.)  Same settle /
// batch / idempotency contract as the other rollups, on its own cursor.
func RollupInstallWideBlocked(ctx context.Context, d *db.DB) error {
	if d == nil {
		return nil
	}
	cursor, err := stateCursor(ctx, d, installWideBlockedState)
	if err != nil {
		return err
	}
	nowHour := time.Now().Unix() / 3600
	lastSettled := nowHour - trafficSettleHours
	floor := nowHour - int64(hourlyKeep)*24
	start := cursor + 1
	if start < floor {
		start = floor
	}
	for start <= lastSettled {
		end := start + trafficRollupBatchHours - 1
		if end > lastSettled {
			end = lastSettled
		}
		if err := rollupInstallWideBlockedRange(ctx, d, start, end); err != nil {
			return err
		}
		start = end + 1
	}
	return nil
}

func rollupInstallWideBlockedRange(ctx context.Context, d *db.DB, fromHour, toHour int64) error {
	rows, err := d.QueryContext(ctx,
		`SELECT bucket_min, kind, sketch FROM unmask_traffic_hll
		 WHERE kind IN ('ipc','ipp','ipb') AND bucket_min >= ? AND bucket_min < ?`,
		fromHour*60, (toHour+1)*60)
	if err != nil {
		return err
	}
	type hourKind struct {
		hour int64
		kind string
	}
	by := map[hourKind]*hll{}
	for rows.Next() {
		var bm int64
		var kind string
		var blob []byte
		if err := rows.Scan(&bm, &kind, &blob); err != nil {
			rows.Close()
			return err
		}
		k := hourKind{bm / 60, kind}
		s := by[k]
		if s == nil {
			s = &hll{}
			by[k] = s
		}
		s.mergeBytes(blob)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	sqlite := d.Driver == db.DriverSQLite
	up := `INSERT INTO unmask_aggregate_hll (bucket, bucket_kind, bucket_key, sketch) VALUES (?, ?, ?, ?)`
	if sqlite {
		up += ` ON CONFLICT(bucket, bucket_kind, bucket_key) DO UPDATE SET sketch = excluded.sketch`
	} else {
		up += ` ON DUPLICATE KEY UPDATE sketch = VALUES(sketch)`
	}
	stmt, err := tx.PrepareContext(ctx, up)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, s := range by {
		bucket := time.Unix(k.hour*3600, 0).UTC().Format("2006-01-02 15")
		if _, err := stmt.ExecContext(ctx, bucket, hkTrafficBlockedAll, k.kind, s[:]); err != nil {
			return err
		}
	}
	st := `INSERT INTO unmask_aggregate_state (name, last_id, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`
	if sqlite {
		st += ` ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id, updated_at = excluded.updated_at`
	} else {
		st += ` ON DUPLICATE KEY UPDATE last_id = VALUES(last_id), updated_at = VALUES(updated_at)`
	}
	if _, err := tx.ExecContext(ctx, st, installWideBlockedState, toHour); err != nil {
		return err
	}
	return tx.Commit()
}

// mergeInstallWideHLL merges the install-wide hourly distinct-IP sketch for one
// traffic kind over [cutoffMin, untilMin]: settled hours from the rollup
// (bucketKind/bucketKey on cursorState) plus a live per-minute tail straight
// from unmask_traffic_hll (all sites).  Falls back to the whole window live when
// the rollup has not run yet (cursor < 0).
func mergeInstallWideHLL(ctx context.Context, d *db.DB, kind, bucketKind, bucketKey, cursorState string, cutoffMin, untilMin int64) (*hll, error) {
	out := &hll{}
	cursor, err := stateCursor(ctx, d, cursorState)
	if err != nil {
		return nil, err
	}
	liveMin := cutoffMin
	if cursor >= 0 {
		cutoffHour := time.Unix(cutoffMin*60, 0).UTC().Format("2006-01-02 15")
		upToSec := cursor * 3600
		if u := untilMin * 60; u < upToSec {
			upToSec = u
		}
		upToHour := time.Unix(upToSec, 0).UTC().Format("2006-01-02 15")
		rows, err := d.QueryContext(ctx,
			`SELECT sketch FROM unmask_aggregate_hll
			 WHERE bucket_kind = ? AND bucket_key = ? AND bucket >= ? AND bucket <= ?`,
			bucketKind, bucketKey, cutoffHour, upToHour)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var b []byte
			if err := rows.Scan(&b); err != nil {
				rows.Close()
				return nil, err
			}
			out.mergeBytes(b)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		if m := (cursor + 1) * 60; m > liveMin {
			liveMin = m
		}
	}
	rows, err := d.QueryContext(ctx,
		`SELECT sketch FROM unmask_traffic_hll WHERE kind = ? AND bucket_min >= ? AND bucket_min <= ?`,
		kind, liveMin, untilMin)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return nil, err
		}
		out.mergeBytes(b)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	return out, nil
}

// TrafficUniqueAgg computes the overview's non-human-% figures for the default
// (all-sites) view from the install-wide rollups instead of scanning every
// site's per-minute sketches:
//
//	total   = distinct client IPs over all traffic         (hkTrafficIPAll '')
//	blocked = distinct IPs challenged but never passed      (hkTrafficBlockedAll)
//	        = est(ipc ∪ ipp) − est(ipp)
//	benign  = distinct listed crawlers passed on purpose    (hkTrafficBlockedAll)
//
// ok=false when there is no traffic-sketch data at all (access-log feed off /
// just deployed) so the caller renders "—".  minutes is a trailing window.
func TrafficUniqueAgg(ctx context.Context, d *db.DB, minutes int) (total, blocked, benign int, ok bool, err error) {
	untilMin := time.Now().Unix() / 60
	cutoffMin := untilMin - int64(minutes)
	ip, err := mergeInstallWideHLL(ctx, d, "ip", hkTrafficIPAll, "", installWideState, cutoffMin, untilMin)
	if err != nil {
		return 0, 0, 0, false, err
	}
	ipc, err := mergeInstallWideHLL(ctx, d, "ipc", hkTrafficBlockedAll, "ipc", installWideBlockedState, cutoffMin, untilMin)
	if err != nil {
		return 0, 0, 0, false, err
	}
	ipp, err := mergeInstallWideHLL(ctx, d, "ipp", hkTrafficBlockedAll, "ipp", installWideBlockedState, cutoffMin, untilMin)
	if err != nil {
		return 0, 0, 0, false, err
	}
	ipb, err := mergeInstallWideHLL(ctx, d, "ipb", hkTrafficBlockedAll, "ipb", installWideBlockedState, cutoffMin, untilMin)
	if err != nil {
		return 0, 0, 0, false, err
	}
	total = ip.estimate()
	// HLL has no subtraction, so est(ipc \ ipp) = est(ipc ∪ ipp) − est(ipp).
	union := &hll{}
	union.merge(ipc)
	union.merge(ipp)
	blocked = union.estimate() - ipp.estimate()
	if blocked < 0 {
		blocked = 0
	}
	// Benign: listed crawlers this install passed without challenging.  A
	// direct estimate, not a subtraction, so it carries only the sketch's own
	// error rather than the difference of two.
	benign = ipb.estimate()
	// ip ⊇ ipc ⊇ (challenged), so total>0 iff there was any traffic sketch at all
	// — mirrors trafficUnique's "no ip sketch -> —".
	return total, blocked, benign, total > 0, nil
}

// BenignStartMin: the oldest minute bucket carrying a benign-crawler ('ipb')
// sketch, as a unix minute.  ok=false when none exists yet.
//
// The benign half of the overview's non-human split only starts accruing when
// the release that introduced it begins reading the access log -- there is no
// way to backfill it, because nothing before then recorded which passed
// clients were listed crawlers.  Until it spans the whole window the count is
// a fraction of a period the tile labels 24h, which reads as a wrong number
// rather than a young one: on the first fleet install it showed 67 benign
// against 2,031 malicious while covering 40 minutes against 24 hours.  The
// caller uses this to say "collecting" instead.
//
// Reads the per-minute table for both the site and install-wide paths: it is
// the source both derive from, and idx_unmask_traffic_hll_kind_bucket makes
// the MIN a single index seek.
func BenignStartMin(ctx context.Context, d *db.DB) (int64, bool) {
	if d == nil {
		return 0, false
	}
	var min sql.NullInt64
	if err := d.QueryRowContext(ctx,
		`SELECT MIN(bucket_min) FROM unmask_traffic_hll WHERE kind = 'ipb'`).Scan(&min); err != nil {
		log.Printf("BenignStartMin: %v", err)
		return 0, false
	}
	if !min.Valid {
		return 0, false
	}
	return min.Int64, true
}
