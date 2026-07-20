package dashboard

import (
	"context"
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
