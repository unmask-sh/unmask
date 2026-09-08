package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// RebuildResult is what RebuildEvents did.
type RebuildResult struct {
	Kept    int64         // rows copied into the new table
	Indexes int           // indexes recreated
	Elapsed time.Duration // wall time
}

// RebuildEvents drops every unmask_event row older than the retention window
// by copying the rows to keep into a fresh table and discarding the old one --
// the way to clear a backlog that dwarfs the window.  Deleting row by row costs
// eight index updates per row at random pages; copying the window is a
// sequential read, dropping the old table frees its pages in one step, and
// each index is rebuilt by one sorted pass.  Measured on 2026-09-08 numbers
// (a 36 GB file holding ~20 days against a 7-day window) this is minutes
// against hours.
//
// Offline only: it takes an exclusive transaction for the swap and the file's
// row ids continue from where they were (sqlite_sequence is carried over), but
// a daemon writing meanwhile would insert into the table being dropped.  The
// caller (`unmask db-prune -mode rebuild`) checks that nobody has the socket.
// SQLite only.
func RebuildEvents(ctx context.Context, d *db.DB, retentionDays int, progress func(string)) (res RebuildResult, err error) {
	if d == nil || d.Driver != db.DriverSQLite {
		return res, errors.New("rebuild: SQLite only")
	}
	if retentionDays <= 0 {
		return res, errors.New("rebuild: retention must be positive")
	}
	say := func(f string, a ...any) {
		if progress != nil {
			progress(fmt.Sprintf(f, a...))
		}
	}
	start := time.Now()
	defer func() { res.Elapsed = time.Since(start) }()
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)

	// The table and its indexes exactly as the schema has them: the new table
	// is created from the stored CREATE statement with only the name changed,
	// so columns, defaults and the column comments come along.
	var createSQL string
	if err := d.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='unmask_event'`).Scan(&createSQL); err != nil {
		return res, fmt.Errorf("rebuild: read table schema: %w", err)
	}
	newCreate, ok := renameInCreate(createSQL, "unmask_event", "unmask_event_rebuild")
	if !ok {
		return res, errors.New("rebuild: unexpected CREATE TABLE text for unmask_event")
	}
	rows, qerr := d.QueryContext(ctx, `SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='unmask_event' AND sql IS NOT NULL ORDER BY name`)
	if qerr != nil {
		return res, fmt.Errorf("rebuild: read indexes: %w", qerr)
	}
	var indexSQL []string
	for rows.Next() {
		var name, sqlText string
		if err := rows.Scan(&name, &sqlText); err != nil {
			rows.Close()
			return res, err
		}
		indexSQL = append(indexSQL, sqlText)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	var triggers int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='unmask_event'`).Scan(&triggers); err != nil {
		return res, err
	}
	if triggers > 0 {
		return res, errors.New("rebuild: unmask_event has triggers; refusing to rebuild")
	}

	// A leftover from an interrupted rebuild is discarded, not resumed: the
	// copy below is the whole answer.
	if _, err := d.ExecContext(ctx, `DROP TABLE IF EXISTS unmask_event_rebuild`); err != nil {
		return res, err
	}
	if _, err := d.ExecContext(ctx, newCreate); err != nil {
		return res, fmt.Errorf("rebuild: create: %w", err)
	}
	say("copying rows newer than %s into the new table", cutoff.Format("2006-01-02 15:04:05"))
	t0 := time.Now()
	r, err := d.ExecContext(ctx, `INSERT INTO unmask_event_rebuild SELECT * FROM unmask_event WHERE date_created >= ? ORDER BY id`, cutoff)
	if err != nil {
		_, _ = d.ExecContext(context.Background(), `DROP TABLE IF EXISTS unmask_event_rebuild`)
		return res, fmt.Errorf("rebuild: copy: %w", err)
	}
	res.Kept, _ = r.RowsAffected()
	say("copied %d rows in %v", res.Kept, time.Since(t0).Round(time.Millisecond))

	// The swap: one exclusive transaction so a reader never sees the table
	// missing.  The sequence carries over so ids keep climbing (--ref
	// lookups and the hunt log key on them).
	tx, terr := d.BeginTx(ctx, nil)
	if terr != nil {
		return res, terr
	}
	swap := []string{
		`DROP TABLE unmask_event`,
		`ALTER TABLE unmask_event_rebuild RENAME TO unmask_event`,
	}
	for _, q := range swap {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			tx.Rollback()
			return res, fmt.Errorf("rebuild: swap: %w", err)
		}
	}
	// A rename moves the sqlite_sequence row along; make sure the counter is
	// at least the highest id kept either way.
	if _, err := tx.ExecContext(ctx, `INSERT INTO sqlite_sequence(name, seq) SELECT 'unmask_event', COALESCE(MAX(id), 0) FROM unmask_event WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='unmask_event')`); err != nil {
		tx.Rollback()
		return res, fmt.Errorf("rebuild: sequence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sqlite_sequence SET seq = (SELECT COALESCE(MAX(id), 0) FROM unmask_event) WHERE name='unmask_event' AND seq < (SELECT COALESCE(MAX(id), 0) FROM unmask_event)`); err != nil {
		tx.Rollback()
		return res, fmt.Errorf("rebuild: sequence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	for _, q := range indexSQL {
		t1 := time.Now()
		if _, err := d.ExecContext(ctx, q); err != nil {
			return res, fmt.Errorf("rebuild: index: %w (%s)", err, q)
		}
		res.Indexes++
		say("index %d/%d rebuilt in %v", res.Indexes, len(indexSQL), time.Since(t1).Round(time.Millisecond))
	}
	pruneCheckpointWAL(ctx, d, res.Kept)
	return res, nil
}

// renameInCreate rewrites the table name in a stored CREATE TABLE statement.
// Only the name token right after "CREATE TABLE [IF NOT EXISTS]" changes; a
// column comment mentioning the table is left alone.
func renameInCreate(createSQL, from, to string) (string, bool) {
	head := createSQL
	upper := strings.ToUpper(head)
	i := strings.Index(upper, "CREATE TABLE")
	if i < 0 {
		return "", false
	}
	j := i + len("CREATE TABLE")
	rest := head[j:]
	trim := strings.TrimLeft(rest, " \t\r\n")
	if strings.HasPrefix(strings.ToUpper(trim), "IF NOT EXISTS") {
		trim = strings.TrimLeft(trim[len("IF NOT EXISTS"):], " \t\r\n")
	}
	// The name may be bare or quoted with " ` [ ].
	name := trim
	for _, q := range []string{`"`, "`", "["} {
		if strings.HasPrefix(name, q) {
			closeQ := q
			if q == "[" {
				closeQ = "]"
			}
			end := strings.Index(name[1:], closeQ)
			if end < 0 {
				return "", false
			}
			if name[1:1+end] != from {
				return "", false
			}
			return head[:len(head)-len(trim)] + q + to + closeQ + name[2+end:], true
		}
	}
	if !strings.HasPrefix(name, from) {
		return "", false
	}
	after := name[len(from):]
	if after != "" && (after[0] == '_' || (after[0] >= 'a' && after[0] <= 'z') || (after[0] >= 'A' && after[0] <= 'Z') || (after[0] >= '0' && after[0] <= '9')) {
		return "", false
	}
	return head[:len(head)-len(trim)] + to + after, true
}
