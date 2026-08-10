package events

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func pruneTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "p.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}

func seedEvents(t *testing.T, d *db.DB, n int, when time.Time) {
	t.Helper()
	ts := when.UTC().Format("2006-01-02 15:04:05.000")
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := tx.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'UA','','ok',0,'serve',0,0,'','','{}',?)`,
			[]byte{10, 0, byte(i >> 8), byte(i)}, ts); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func countEvents(t *testing.T, d *db.DB) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The retention prune deletes in bounded batches so the write lock is never
// held for a whole multi-million-row DELETE (which starved BAN lookups into
// failing open, and rolled back whole at the caller's deadline -- so a big
// backlog never drained).  Pinned here: several batches drain the backlog
// completely, rows inside the window survive, and the checkpoint path runs
// without error.
func TestPruneOldEventsBatched(t *testing.T) {
	d := pruneTestDB(t)
	old := time.Now().Add(-10 * 24 * time.Hour)
	seedEvents(t, d, 230, old)                       // 3 batches at 100/batch
	seedEvents(t, d, 20, time.Now().Add(-time.Hour)) // must survive

	origRows, origPause, origCkpt := pruneBatchRows, pruneBatchPause, pruneCheckpointRows
	pruneBatchRows, pruneBatchPause, pruneCheckpointRows = 100, time.Millisecond, 1
	defer func() {
		pruneBatchRows, pruneBatchPause, pruneCheckpointRows = origRows, origPause, origCkpt
	}()

	n, err := PruneOldEvents(context.Background(), d, 7)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 230 {
		t.Errorf("deleted %d rows, want 230 (the multi-batch loop must drain the whole backlog)", n)
	}
	if got := countEvents(t, d); got != 20 {
		t.Errorf("%d rows remain, want the 20 inside the window", got)
	}
}

// A canceled context stops the loop, and what was already deleted stays
// deleted -- the property the old single-statement DELETE lacked (its rollback
// threw away every row of progress, so a backlog bigger than the deadline
// never shrank).  The cancel lands in the first inter-batch pause: the batch
// itself is milliseconds against a 200ms pause, so the timing has a wide
// margin, and the assertion is the invariant (remaining == seeded - reported)
// rather than an exact batch count.
func TestPruneOldEventsCancelKeepsProgress(t *testing.T) {
	d := pruneTestDB(t)
	seedEvents(t, d, 250, time.Now().Add(-10*24*time.Hour))

	origRows, origPause := pruneBatchRows, pruneBatchPause
	pruneBatchRows, pruneBatchPause = 100, 200*time.Millisecond
	defer func() { pruneBatchRows, pruneBatchPause = origRows, origPause }()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	n, err := PruneOldEvents(ctx, d, 7)
	if err == nil {
		t.Fatal("want a context error from a canceled run")
	}
	if n >= 250 {
		t.Fatalf("reported %d deletions -- the cancel should have stopped the loop early", n)
	}
	if got, want := countEvents(t, d), 250-int(n); got != want {
		t.Errorf("%d rows remain but %d were reported deleted (want remaining == seeded - reported: committed batches must survive the cancel)", got, n)
	}

	// And the next run -- the daily retry -- drains the rest.
	n2, err := PruneOldEvents(context.Background(), d, 7)
	if err != nil {
		t.Fatalf("follow-up prune: %v", err)
	}
	if n+n2 != 250 || countEvents(t, d) != 0 {
		t.Errorf("runs deleted %d + %d, remaining=%d; want the follow-up run to finish the backlog", n, n2, countEvents(t, d))
	}
}

// Guards: a nil retention is a no-op, and MariaDB would take the DELETE..LIMIT
// branch (not executable here -- sqlite-only test rig -- but the statement
// split is pinned by the driver check in PruneOldEvents itself).
func TestPruneOldEventsNoop(t *testing.T) {
	d := pruneTestDB(t)
	seedEvents(t, d, 5, time.Now().Add(-10*24*time.Hour))
	if n, err := PruneOldEvents(context.Background(), d, 0); n != 0 || err != nil {
		t.Errorf("retention 0 must be a no-op, got n=%d err=%v", n, err)
	}
	if got := countEvents(t, d); got != 5 {
		t.Errorf("no-op deleted rows: %d remain, want 5", got)
	}
}
