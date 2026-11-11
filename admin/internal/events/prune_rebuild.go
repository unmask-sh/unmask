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

	// A rebuild stopped after its swap left indexes to create: they come
	// first, so the table's schema read below is whole again.
	if n, err := FinishRebuildIndexes(ctx, d, say); err != nil {
		return res, err
	} else if n > 0 {
		say("created %d index(es) an interrupted rebuild had left", n)
	}

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
	var indexes [][2]string // name, CREATE INDEX statement
	for rows.Next() {
		var name, sqlText string
		if err := rows.Scan(&name, &sqlText); err != nil {
			rows.Close()
			return res, err
		}
		indexes = append(indexes, [2]string{name, sqlText})
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
	r, err := d.ExecContext(ctx, rebuildCopySQL, cutoff)
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
	// The counter the old table reached, taken before the drop takes its
	// sqlite_sequence row: the new one goes on from the higher of that and
	// the highest id kept.  A rebuild that kept no row restarted the ids at
	// 1, under the hourly aggregate's cursor, which then skipped every new
	// row while it reported itself caught up.
	var oldSeq int64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(COALESCE((SELECT MAX(seq) FROM sqlite_sequence WHERE name='unmask_event'), 0), COALESCE((SELECT MAX(id) FROM unmask_event), 0))`).Scan(&oldSeq); err != nil {
		tx.Rollback()
		return res, fmt.Errorf("rebuild: sequence: %w", err)
	}
	swap := []string{
		`DROP TABLE unmask_event`,
		`ALTER TABLE unmask_event_rebuild RENAME TO unmask_event`,
		`DELETE FROM sqlite_sequence WHERE name='unmask_event'`,
		// The indexes to create, recorded with the swap: a rebuild stopped
		// before it created them all left the table without them for good
		// -- the next start does not create them and the next rebuild read
		// the table as it found it.  FinishRebuildIndexes works the list.
		rebuildPendingCreate,
	}
	for _, q := range swap {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			tx.Rollback()
			return res, fmt.Errorf("rebuild: swap: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sqlite_sequence(name, seq) SELECT 'unmask_event', MAX(?, COALESCE((SELECT MAX(id) FROM unmask_event), 0))`, oldSeq); err != nil {
		tx.Rollback()
		return res, fmt.Errorf("rebuild: sequence: %w", err)
	}
	for _, ix := range indexes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+rebuildPendingTable+`(name, sql) VALUES (?, ?)`, ix[0], ix[1]); err != nil {
			tx.Rollback()
			return res, fmt.Errorf("rebuild: record the indexes: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	n, err := FinishRebuildIndexes(ctx, d, say)
	res.Indexes = n
	if err != nil {
		return res, err
	}
	pruneCheckpointWAL(ctx, d, res.Kept)
	return res, nil
}

// rebuildPendingTable lists the indexes a rebuild has still to create on
// the new unmask_event; it exists only between a rebuild's swap and its
// last index (RebuildEvents, FinishRebuildIndexes).
const rebuildPendingTable = "unmask_event_rebuild_indexes"

const rebuildPendingCreate = `CREATE TABLE IF NOT EXISTS ` + rebuildPendingTable + ` (
    name TEXT PRIMARY KEY,  -- the index's name, as sqlite_master had it on the old unmask_event
    sql  TEXT NOT NULL      -- its CREATE INDEX statement, run on the new table and then deleted from here
)`

// FinishRebuildIndexes creates the indexes a rebuild recorded and has not
// created yet, deleting each from the list once it exists, and drops the
// list when it is empty.  It returns how many it created; 0 with no list.
// Run by the rebuild after its swap, and first by the next one when a
// rebuild was stopped halfway.
func FinishRebuildIndexes(ctx context.Context, d *db.DB, say func(string, ...any)) (int, error) {
	pending, err := PendingRebuildIndexes(ctx, d)
	if err != nil || len(pending) == 0 {
		return 0, err
	}
	created := 0
	for i, ix := range pending {
		var exists int
		if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, ix[0]).Scan(&exists); err != nil {
			return created, err
		}
		if exists == 0 {
			t1 := time.Now()
			if _, err := d.ExecContext(ctx, ix[1]); err != nil {
				return created, fmt.Errorf("rebuild: index: %w (%s)", err, ix[1])
			}
			created++
			if say != nil {
				say("index %d/%d rebuilt in %v", i+1, len(pending), time.Since(t1).Round(time.Millisecond))
			}
		}
		if _, err := d.ExecContext(ctx, `DELETE FROM `+rebuildPendingTable+` WHERE name = ?`, ix[0]); err != nil {
			return created, err
		}
	}
	if _, err := d.ExecContext(ctx, `DROP TABLE IF EXISTS `+rebuildPendingTable); err != nil {
		return created, err
	}
	return created, nil
}

// PendingRebuildIndexes: the indexes an interrupted rebuild left to create
// (name, statement), none when no rebuild was stopped halfway.
func PendingRebuildIndexes(ctx context.Context, d *db.DB) ([][2]string, error) {
	if d == nil || d.Driver != db.DriverSQLite {
		return nil, nil
	}
	var n int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, rebuildPendingTable).Scan(&n); err != nil || n == 0 {
		return nil, err
	}
	rows, err := d.QueryContext(ctx, `SELECT name, sql FROM `+rebuildPendingTable+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var name, sqlText string
		if err := rows.Scan(&name, &sqlText); err != nil {
			return nil, err
		}
		out = append(out, [2]string{name, sqlText})
	}
	return out, rows.Err()
}

// rebuildCopySQL is the copy.  NOT INDEXED pins the plan to a walk of the
// table in rowid order, which satisfies the ORDER BY as it goes: the
// alternative -- the date index, then a sort -- puts every kept row through
// SQLite's sorter, and the sorter's working set is the whole result.  A full
// read of the old table is sequential I/O, once; sorting gigabytes is what
// took the memory (see db.OpenMaintenance).  The kept rows land in the new
// table in id order, so its b-tree is built by appends.
const rebuildCopySQL = `INSERT INTO unmask_event_rebuild SELECT * FROM unmask_event NOT INDEXED WHERE date_created >= ? ORDER BY id`

// RebuildEstimate sizes a rebuild before it starts: how many rows the window
// keeps against how many the table holds, so the caller can put the kept
// share of the live bytes against the free space -- the new table is written
// before the old one is dropped.  The total is the id span: instant on the
// rowid b-tree where COUNT(*) walks an index, and close, since the daemon's
// own prune takes rows from the low end and leaves no holes worth counting.
func RebuildEstimate(ctx context.Context, d *db.DB, retentionDays int) (kept, total int64, err error) {
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	if err = d.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_event WHERE date_created >= ?`, cutoff).Scan(&kept); err != nil {
		return 0, 0, fmt.Errorf("rebuild estimate: %w", err)
	}
	if err = d.QueryRowContext(ctx, `SELECT COALESCE(MAX(id) - MIN(id) + 1, 0) FROM unmask_event`).Scan(&total); err != nil {
		return 0, 0, fmt.Errorf("rebuild estimate: %w", err)
	}
	if total < kept {
		total = kept
	}
	return kept, total, nil
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
