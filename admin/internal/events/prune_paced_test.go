package events

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// smallChunks makes the paced loop take many chunks over a few hundred rows
// and restores the shipped knobs afterwards.
func smallChunks(t *testing.T) {
	t.Helper()
	oStart, oMin, oMax, oYield, oBackoff, oCkpt := pruneChunkStart, pruneChunkMin, pruneChunkMax, pruneYieldMin, pruneBusyBackoff, pruneCheckpointRows
	pruneChunkStart, pruneChunkMin, pruneChunkMax = 40, 10, 100
	pruneYieldMin, pruneBusyBackoff, pruneCheckpointRows = time.Millisecond, 5*time.Millisecond, 1
	t.Cleanup(func() {
		pruneChunkStart, pruneChunkMin, pruneChunkMax, pruneYieldMin, pruneBusyBackoff, pruneCheckpointRows = oStart, oMin, oMax, oYield, oBackoff, oCkpt
	})
}

// The paced loop drains a backlog in rowid order and reports Done; rows
// inside the window and rows newer than the run's upper bound survive.
func TestPruneOldEventsOptsDrainsInOrder(t *testing.T) {
	smallChunks(t)
	d := pruneTestDB(t)
	seedEvents(t, d, 230, time.Now().Add(-20*24*time.Hour))
	seedEvents(t, d, 20, time.Now().Add(-time.Hour))
	seedEvents(t, d, 7, time.Now().Add(-9*24*time.Hour)) // old rows above the window's rows: caught by the bound too
	res, err := PruneOldEventsOpts(context.Background(), d, 7, PruneOptions{})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 237 || !res.Done {
		t.Errorf("deleted=%d done=%v, want 237 rows deleted and Done", res.Deleted, res.Done)
	}
	if res.Chunks < 3 {
		t.Errorf("want several chunks with a 40-row start, got %d", res.Chunks)
	}
	if got := countEvents(t, d); got != 20 {
		t.Errorf("%d rows remain, want the 20 inside the window", got)
	}
	// Nothing older than the window is left: a second run finds nothing.
	res2, err := PruneOldEventsOpts(context.Background(), d, 7, PruneOptions{})
	if err != nil || res2.Deleted != 0 || !res2.Done {
		t.Errorf("second run: deleted=%d done=%v err=%v, want 0 / Done", res2.Deleted, res2.Done, err)
	}
}

// A chunk refused with SQLITE_BUSY is retried, not fatal: the run goes on
// and ends Done, counting the retries.  Injected through pruneExec so no
// second writer is needed.
func TestPruneOldEventsOptsRetriesBusy(t *testing.T) {
	smallChunks(t)
	d := pruneTestDB(t)
	seedEvents(t, d, 150, time.Now().Add(-20*24*time.Hour))
	orig := pruneExec
	t.Cleanup(func() { pruneExec = orig })
	fails := 3
	pruneExec = func(ctx context.Context, d *db.DB, q string, args ...any) (sql.Result, error) {
		if fails > 0 && len(args) == 3 { // the DELETE (a PRAGMA has no args)
			fails--
			return nil, errors.New("database is locked (5) (SQLITE_BUSY)")
		}
		return orig(ctx, d, q, args...)
	}
	res, err := PruneOldEventsOpts(context.Background(), d, 7, PruneOptions{})
	if err != nil {
		t.Fatalf("a busy chunk must be retried, got %v", err)
	}
	if res.BusyRetries != 3 || res.Deleted != 150 || !res.Done {
		t.Errorf("retries=%d deleted=%d done=%v, want 3 / 150 / Done", res.BusyRetries, res.Deleted, res.Done)
	}
	if countEvents(t, d) != 0 {
		t.Errorf("%d rows remain", countEvents(t, d))
	}
}

// Past the retry budget the run stops with the error and what it deleted so
// far stays deleted; the next run continues.
func TestPruneOldEventsOptsGivesUpAfterRetries(t *testing.T) {
	smallChunks(t)
	d := pruneTestDB(t)
	seedEvents(t, d, 150, time.Now().Add(-20*24*time.Hour))
	orig := pruneExec
	t.Cleanup(func() { pruneExec = orig })
	calls := 0
	pruneExec = func(ctx context.Context, d *db.DB, q string, args ...any) (sql.Result, error) {
		if len(args) == 3 {
			calls++
			if calls > 1 { // first chunk commits, every later one is refused
				return nil, errors.New("database is locked (5) (SQLITE_BUSY)")
			}
		}
		return orig(ctx, d, q, args...)
	}
	res, err := PruneOldEventsOpts(context.Background(), d, 7, PruneOptions{})
	if err == nil || !isBusyErr(err) {
		t.Fatalf("want the busy error after the retries, got %v", err)
	}
	if res.Done || res.Deleted != 40 || res.BusyRetries != pruneBusyRetries {
		t.Errorf("deleted=%d done=%v retries=%d, want 40 / not Done / %d retries", res.Deleted, res.Done, res.BusyRetries, pruneBusyRetries)
	}
	pruneExec = orig
	res2, err := PruneOldEventsOpts(context.Background(), d, 7, PruneOptions{})
	if err != nil || res2.Deleted != 110 || !res2.Done {
		t.Errorf("follow-up run: deleted=%d done=%v err=%v, want 110 / Done", res2.Deleted, res2.Done, err)
	}
}

// Offline mode starts at the largest chunk and never yields.
func TestPruneOldEventsOptsOffline(t *testing.T) {
	smallChunks(t)
	d := pruneTestDB(t)
	seedEvents(t, d, 250, time.Now().Add(-20*24*time.Hour))
	var seen []int64
	res, err := PruneOldEventsOpts(context.Background(), d, 7, PruneOptions{Offline: true, Progress: func(r PruneResult) { seen = append(seen, r.Deleted) }})
	if err != nil {
		t.Fatal(err)
	}
	if res.Chunks != 3 || res.Deleted != 250 || !res.Done {
		t.Errorf("chunks=%d deleted=%d done=%v, want 3 chunks of up to 100 rows", res.Chunks, res.Deleted, res.Done)
	}
	if len(seen) != 3 || seen[0] != 100 {
		t.Errorf("progress after every chunk, got %v", seen)
	}
}

// The rebuild keeps exactly the window, keeps the schema (every index, the
// row-id sequence) and leaves a database that passes integrity_check.
func TestRebuildEvents(t *testing.T) {
	d := pruneTestDB(t)
	seedEvents(t, d, 300, time.Now().Add(-20*24*time.Hour))
	seedEvents(t, d, 25, time.Now().Add(-time.Hour))
	var before []string
	rows, err := d.Query(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='unmask_event' AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		before = append(before, n)
	}
	rows.Close()
	var maxID int64
	_ = d.QueryRow(`SELECT MAX(id) FROM unmask_event`).Scan(&maxID)

	var msgs []string
	res, err := RebuildEvents(context.Background(), d, 7, func(m string) { msgs = append(msgs, m) })
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if res.Kept != 25 || res.Indexes != len(before) {
		t.Errorf("kept=%d indexes=%d, want 25 / %d", res.Kept, res.Indexes, len(before))
	}
	if got := countEvents(t, d); got != 25 {
		t.Errorf("%d rows remain, want 25", got)
	}
	var after []string
	rows, err = d.Query(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='unmask_event' AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		after = append(after, n)
	}
	rows.Close()
	if len(after) != len(before) {
		t.Errorf("indexes before=%v after=%v", before, after)
	}
	for i := range before {
		if i < len(after) && before[i] != after[i] {
			t.Errorf("index %d: before=%s after=%s", i, before[i], after[i])
		}
	}
	var leftover int
	_ = d.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='unmask_event_rebuild'`).Scan(&leftover)
	if leftover != 0 {
		t.Errorf("the temporary table must be gone")
	}
	// New rows keep climbing past the old maximum id.
	seedEvents(t, d, 1, time.Now())
	var newMax int64
	_ = d.QueryRow(`SELECT MAX(id) FROM unmask_event`).Scan(&newMax)
	if newMax <= maxID {
		t.Errorf("row ids must continue past %d, got %d", maxID, newMax)
	}
	var integrity string
	if err := d.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Errorf("integrity_check: %q %v", integrity, err)
	}
	if len(msgs) == 0 {
		t.Errorf("progress messages expected")
	}
}

func TestRenameInCreate(t *testing.T) {
	cases := []struct{ in, want string }{
		{`CREATE TABLE unmask_event (id INTEGER)`, `CREATE TABLE unmask_event_rebuild (id INTEGER)`},
		{`CREATE TABLE IF NOT EXISTS unmask_event (
    id INTEGER -- the unmask_event row id
)`, `CREATE TABLE IF NOT EXISTS unmask_event_rebuild (
    id INTEGER -- the unmask_event row id
)`},
		{`CREATE TABLE "unmask_event" (id INTEGER)`, `CREATE TABLE "unmask_event_rebuild" (id INTEGER)`},
	}
	for _, c := range cases {
		got, ok := renameInCreate(c.in, "unmask_event", "unmask_event_rebuild")
		if !ok || got != c.want {
			t.Errorf("renameInCreate(%q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
	if _, ok := renameInCreate(`CREATE TABLE unmask_eventx (id INTEGER)`, "unmask_event", "x"); ok {
		t.Errorf("a longer name must not match")
	}
}

func TestIsBusyErr(t *testing.T) {
	for _, s := range []string{"database is locked (5) (SQLITE_BUSY)", "Error 1205: Lock wait timeout exceeded", "Error 1213: Deadlock found when trying to get lock"} {
		if !isBusyErr(errors.New(s)) {
			t.Errorf("%q must read as busy", s)
		}
	}
	if isBusyErr(errors.New("no such table: unmask_event")) || isBusyErr(nil) {
		t.Errorf("only lock errors are busy")
	}
}
