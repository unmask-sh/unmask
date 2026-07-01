package dashboard

import (
	"context"
	"database/sql"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

const (
	// trafficIPState is the unmask_aggregate_state.name whose last_id holds the
	// last UTC unix-hour whose per-minute traffic sketches have been folded into
	// unmask_aggregate_hll(bucket_kind=hkTrafficIP).
	trafficIPState = "traffic_ip"
	// trafficSettleHours keeps the most recent hours out of the rollup so late
	// log datagrams (nginxlog flushes a past minute read-merge-write, so a
	// minute bucket can still grow after its minute passes) settle before that
	// hour is frozen into an hourly sketch. Hours newer than this are read live
	// from the per-minute table by DailyUniqueIPs, so they never lag either.
	trafficSettleHours = 2
	// trafficRollupBatchHours bounds how many hours one rollup pass folds (and
	// holds a write tx for) at a time, so the first-run backfill of the whole
	// retained history commits incrementally instead of in one long-locked tx.
	trafficRollupBatchHours = 48
)

// RollupTrafficHLL pre-merges the per-minute unmask_traffic_hll(kind='ip')
// sketches into hourly sketches in unmask_aggregate_hll(bucket_kind=hkTrafficIP,
// bucket=<UTC 'YYYY-MM-DD HH'>, bucket_key=<site>). DailyUniqueIPs then merges
// ~24 hourly sketches per day plus a short live tail instead of ~1440
// per-minute rows per day (~65k for the 30-day view), which took ~15s under
// pure-Go SQLite — long enough to trip the dashboard card's per-query timeout.
//
// It is the single writer of the hkTrafficIP rows, driven by the admin's 60s
// ticker plus a startup run. last_id in unmask_aggregate_state name=trafficIPState
// is the last settled UTC unix-hour folded; each pass folds the hours from
// there up to (now - trafficSettleHours) and advances the cursor per committed
// batch. Idempotent: a batch recomputes each hour's sketch from scratch and
// overwrites, and the cursor only advances after the batch commits, so a crash
// never loses or double-counts. The hkTrafficIP rows share the 'YYYY-MM-DD HH'
// bucket format with the other hourly sketches, so PruneHourly already trims
// them at the 32-day window.
func RollupTrafficHLL(ctx context.Context, d *db.DB) error {
	if d == nil {
		return nil
	}
	cursor, err := trafficRollupCursor(ctx, d)
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
		if err := rollupTrafficRange(ctx, d, start, end); err != nil {
			return err
		}
		start = end + 1
	}
	return nil
}

// rollupTrafficRange folds the per-minute sketches in UTC unix-hours
// [fromHour, toHour] (inclusive) into one hourly sketch per (hour, site) and
// advances the cursor to toHour, all in a single tx.
func rollupTrafficRange(ctx context.Context, d *db.DB, fromHour, toHour int64) error {
	rows, err := d.QueryContext(ctx,
		`SELECT bucket_min, site, sketch FROM unmask_traffic_hll
		 WHERE kind = 'ip' AND bucket_min >= ? AND bucket_min < ?`,
		fromHour*60, (toHour+1)*60)
	if err != nil {
		return err
	}
	type hourSite struct {
		hour int64
		site string
	}
	by := map[hourSite]*hll{}
	for rows.Next() {
		var bm int64
		var site string
		var blob []byte
		if err := rows.Scan(&bm, &site, &blob); err != nil {
			rows.Close()
			return err
		}
		k := hourSite{bm / 60, site}
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
		if _, err := stmt.ExecContext(ctx, bucket, hkTrafficIP, k.site, s[:]); err != nil {
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
	if _, err := tx.ExecContext(ctx, st, trafficIPState, toHour); err != nil {
		return err
	}
	return tx.Commit()
}

// trafficRollupCursor returns the last settled UTC unix-hour folded into
// hkTrafficIP, or -1 when nothing has been rolled yet (= read everything live).
func trafficRollupCursor(ctx context.Context, d *db.DB) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx,
		`SELECT last_id FROM unmask_aggregate_state WHERE name = ?`, trafficIPState).Scan(&id)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return 0, err
	}
	return id, nil
}
