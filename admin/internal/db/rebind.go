package db

import (
	"context"
	"fmt"
)

// RebindAllow atomically consumes one rebind slot for lineage, returning
// whether the rebind may proceed.  Two bounds apply: maxLifetime (total
// rebinds one solve can ever perform) and maxPerHour (a rolling-window rate).
// Both are enforced in a single conditional UPDATE, so concurrent requests --
// the parallel fan-out of one stolen cookie is exactly the attack this bounds
// -- serialize at the database and cannot double-spend a slot.  A cookie-side
// counter could not do this: every fanned-out copy would present the same
// pristine count.  now is unix seconds (UTC).
func RebindAllow(ctx context.Context, conn *DB, lineage, host string, maxLifetime, maxPerHour int, now int64) (bool, error) {
	if lineage == "" {
		return false, nil
	}
	// Ensure the row exists (first rebind for this lineage).
	var ins string
	if conn.Driver == DriverMariaDB {
		ins = "INSERT INTO unmask_rebind_lineage (lineage, host, `count`, window_start, window_count, updated_at) " +
			"VALUES (?, ?, 0, ?, 0, ?) ON DUPLICATE KEY UPDATE lineage = lineage"
	} else {
		ins = "INSERT INTO unmask_rebind_lineage (lineage, host, `count`, window_start, window_count, updated_at) " +
			"VALUES (?, ?, 0, ?, 0, ?) ON CONFLICT (lineage) DO NOTHING"
	}
	if _, err := conn.ExecContext(ctx, ins, lineage, host, now, now); err != nil {
		return false, fmt.Errorf("rebind lineage insert: %w", err)
	}
	// Check + consume in one atomic statement.  The CASE pair restarts the
	// rate window once it is an hour old; the WHERE admits the request iff the
	// lifetime cap is unspent AND (the window has room OR is being restarted).
	res, err := conn.ExecContext(ctx,
		"UPDATE unmask_rebind_lineage SET "+
			"`count` = `count` + 1, "+
			"window_count = CASE WHEN ? - window_start >= 3600 THEN 1 ELSE window_count + 1 END, "+
			"window_start = CASE WHEN ? - window_start >= 3600 THEN ? ELSE window_start END, "+
			"updated_at = ? "+
			"WHERE lineage = ? AND `count` < ? AND (window_count < ? OR ? - window_start >= 3600)",
		now, now, now, now, lineage, maxLifetime, maxPerHour, now)
	if err != nil {
		return false, fmt.Errorf("rebind slot consume: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
