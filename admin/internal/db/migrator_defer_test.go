package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// migratedDB is a fully migrated database in a temporary directory.
func migratedDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := Migrate(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// asBeforeTheIndex turns a migrated database back into one the fingerprint
// index migrations (0032, 0033) have not run on, holding n events: the state
// an install upgrading across them is in.
func asBeforeTheIndex(t *testing.T, d *DB, n int) {
	t.Helper()
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO unmask_event (site, host, ip_address, ja4, phase, date_created)
		VALUES ('s', 'h', X'0A000001', ?, 'serve', CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := stmt.Exec("t13d" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DROP INDEX IF EXISTS idx_unmask_event_ja4_phase`,
		`DELETE FROM schema_migrations WHERE version IN (32, 33)`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.RefreshIndexes(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func hasIndexNow(t *testing.T, d *DB, name string) bool {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func names(ps []PendingMigration) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return strings.Join(out, ",")
}

// TestDeferrableMigrationsAreIndexOnly: the marker is a promise that the
// daemon can run without the migration.  That holds for an index -- it changes
// how fast a read is, never what it returns -- and for nothing else, so a
// marked file may hold CREATE INDEX and DROP INDEX and that is all.  Both
// drivers must mark the same versions, or one of them would wait for an
// operator the other never asks for.
func TestDeferrableMigrationsAreIndexOnly(t *testing.T) {
	marked := map[string]map[int]bool{}
	for _, driver := range []string{"sqlite", "mariadb"} {
		marked[driver] = map[int]bool{}
		entries, err := fs.ReadDir(migrationFS, "migrations/"+driver)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			body, err := fs.ReadFile(migrationFS, "migrations/"+driver+"/"+e.Name())
			if err != nil {
				t.Fatal(err)
			}
			dm := deferMarkerRE.FindSubmatch(body)
			if dm == nil {
				if strings.Contains(string(body), "unmask:deferrable") {
					t.Errorf("%s/%s mentions unmask:deferrable but the line does not parse as the marker", driver, e.Name())
				}
				continue
			}
			if !indexOnly(string(body)) {
				t.Errorf("%s/%s is marked deferrable and holds a statement that is not CREATE INDEX / DROP INDEX: "+
					"a deferred migration may be absent for weeks, and only an index can be", driver, e.Name())
			}
			// The tables approxRows is known to size: unmask_event by its id
			// span; unmask_aggregate_hourly, which has no id, by its rowid span
			// on SQLite and the catalog's count on MariaDB
			// (TestApproxRowsOfATableWithoutAnID).
			if table := string(dm[1]); table != "unmask_event" && table != "unmask_aggregate_hourly" {
				t.Errorf("%s/%s: deferrable on %q, a table the estimate is not known to size (see approxRows)",
					driver, e.Name(), table)
			}
			m := migrationFileRE.FindStringSubmatch(e.Name())
			if m == nil {
				t.Fatalf("%s/%s: unexpected file name", driver, e.Name())
			}
			v := 0
			for _, c := range m[1] {
				v = v*10 + int(c-'0')
			}
			marked[driver][v] = true
		}
	}
	if len(marked["sqlite"]) == 0 {
		t.Fatal("no deferrable migration found: the marker stopped parsing")
	}
	for v := range marked["sqlite"] {
		if !marked["mariadb"][v] {
			t.Errorf("version %d is deferrable on sqlite and not on mariadb", v)
		}
	}
	for v := range marked["mariadb"] {
		if !marked["sqlite"][v] {
			t.Errorf("version %d is deferrable on mariadb and not on sqlite", v)
		}
	}
}

func TestIndexOnly(t *testing.T) {
	for body, want := range map[string]bool{
		"CREATE INDEX IF NOT EXISTS i ON t(a, b);":                  true,
		"DROP INDEX IF EXISTS i;\nCREATE INDEX i ON t(a);":          true,
		"-- a comment\nDROP INDEX IF EXISTS i ON t;":                true,
		"CREATE UNIQUE INDEX i ON t(a);":                            false, // a constraint, not a speed-up
		"ALTER TABLE t ADD COLUMN c TEXT;\nCREATE INDEX i ON t(c);": false,
		"CREATE TABLE IF NOT EXISTS t (id INTEGER);":                false,
		"-- only a comment":                                         false,
		"CREATE INDEX i ON t(a);\nDELETE FROM t;":                   false,
	} {
		if got := indexOnly(body); got != want {
			t.Errorf("indexOnly(%q) = %v, want %v", body, got, want)
		}
	}
}

// TestAppliedIsASetNotAHighWaterMark: a deferred migration is a gap below
// later versions.  Reading "applied" as everything up to the highest recorded
// version would call the gap applied, and the index would never be built.
func TestAppliedIsASetNotAHighWaterMark(t *testing.T) {
	d := migratedDB(t)
	if _, err := d.Exec(`DELETE FROM schema_migrations WHERE version = 32`); err != nil {
		t.Fatal(err)
	}
	pending, err := PendingMigrations(d)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(pending); got != "0032_event_ja4_index" {
		t.Fatalf("pending = %q, want the one version that is missing below 33", got)
	}
	// Its index exists (33 did not drop it), so there is nothing to build.
	if p := pending[0]; len(p.Indexes) != 0 || p.EstHigh != 0 {
		t.Errorf("the index is there: want nothing to build, got indexes %v, estimate %v", p.Indexes, p.EstHigh)
	}
}

// TestDaemonLeavesALongIndexBuildForTheOperator: the daemon applies
// migrations before it listens, so an index build over a large events table
// used to be minutes of no daemon that nobody had been told about.  With
// Defer the build is left unapplied, the daemon runs without the index, and
// the reads that name it drop their hint instead of failing.
func TestDaemonLeavesALongIndexBuildForTheOperator(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)

	var logged []string
	res, err := MigrateWith(d, MigrateOptions{Defer: true, DeferOver: time.Millisecond,
		Logf: func(f string, a ...any) { logged = append(logged, f) }})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(res.Deferred); got != "0032_event_ja4_index,0033_event_ja4_index_order" {
		t.Fatalf("deferred = %q, want both index migrations", got)
	}
	if len(res.Applied) != 0 {
		t.Errorf("applied %v; nothing else was pending", res.Applied)
	}
	first, second := res.Deferred[0], res.Deferred[1]
	if len(first.Indexes) != 1 || first.Indexes[0] != "idx_unmask_event_ja4_phase" {
		t.Errorf("0032 builds %v, want the fingerprint index", first.Indexes)
	}
	if first.Rows != 400 {
		t.Errorf("rows = %d, want the 400 the table holds", first.Rows)
	}
	if first.EstLow <= 0 || first.EstHigh <= first.EstLow {
		t.Errorf("estimate %v..%v is not a range", first.EstLow, first.EstHigh)
	}
	// 0033 repeats 0032's CREATE INDEX IF NOT EXISTS: once 0032 is planned
	// there is nothing left for it to build, and it waits only to keep the
	// pair in order.
	if len(second.Indexes) != 0 || second.EstHigh != 0 {
		t.Errorf("0033 plans %v (%v); 0032 already builds that index", second.Indexes, second.EstHigh)
	}
	if hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Fatal("the index was built although its migration was deferred")
	}
	if got := d.EventJA4IndexHint(); got != "" {
		t.Errorf("hint = %q while the index is absent: the read would fail", got)
	}
	if len(logged) == 0 {
		t.Error("a deferred migration must be logged: the log is where an operator looks first")
	}

	// A second start changes nothing: still pending, still not built.
	res, err = MigrateWith(d, MigrateOptions{Defer: true, DeferOver: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(res.Deferred); got != "0032_event_ja4_index,0033_event_ja4_index_order" {
		t.Fatalf("second start deferred %q", got)
	}
}

// TestSmallTableIsMigratedAtStartup: the threshold is the point.  An install
// whose index builds in a moment must keep upgrading with nothing to do --
// it never sees a notice, and never has a migration waiting.
func TestSmallTableIsMigratedAtStartup(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	res, err := MigrateWith(d, MigrateOptions{Defer: true}) // the default threshold
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deferred) != 0 {
		t.Fatalf("deferred %q on a table of 400 rows", names(res.Deferred))
	}
	if len(res.Applied) != 2 {
		t.Fatalf("applied %v, want both index migrations", res.Applied)
	}
	if !hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Fatal("index not built")
	}
	if got := d.EventJA4IndexHint(); got == "" {
		t.Error("the hint must be back once the index is: MigrateWith re-reads the index list")
	}
}

// TestNegativeThresholdDefersNothing: the way to get the old behaviour.
func TestNegativeThresholdDefersNothing(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	res, err := MigrateWith(d, MigrateOptions{Defer: true, DeferOver: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deferred) != 0 || !hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Fatalf("deferred %q; a negative threshold applies everything at startup", names(res.Deferred))
	}
}

// withExtraMigration adds a migration of the test's own after the shipped
// ones, for the run of one test.
func withExtraMigration(t *testing.T, name, body string) {
	t.Helper()
	m := fstest.MapFS{}
	for _, driver := range []string{"sqlite", "mariadb"} {
		entries, err := fs.ReadDir(embeddedMigrations, "migrations/"+driver)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			p := "migrations/" + driver + "/" + e.Name()
			b, err := fs.ReadFile(embeddedMigrations, p)
			if err != nil {
				t.Fatal(err)
			}
			m[p] = &fstest.MapFile{Data: b}
		}
		m["migrations/"+driver+"/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	prev := migrationFS
	migrationFS = m
	t.Cleanup(func() { migrationFS = prev })
}

// TestSchemaChangesBehindADeferredIndexStillApply: leaving an index out must
// not hold back what comes after it.  A later release's new column is applied
// at startup as always -- by rule it cannot depend on the index -- and when
// the operator then runs the update, only the index is left to do.
func TestSchemaChangesBehindADeferredIndexStillApply(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	withExtraMigration(t, "9001_later_table.sql", "CREATE TABLE IF NOT EXISTS zz_later (id INTEGER PRIMARY KEY);")

	res, err := MigrateWith(d, MigrateOptions{Defer: true, DeferOver: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(res.Deferred); got != "0032_event_ja4_index,0033_event_ja4_index_order" {
		t.Fatalf("deferred = %q", got)
	}
	if len(res.Applied) != 1 || res.Applied[0].Name != "9001_later_table" {
		t.Fatalf("applied %v, want the later schema change", res.Applied)
	}
	if has, _ := hasTable(d, "zz_later"); !has {
		t.Fatal("the later migration's table is missing")
	}

	up, err := ApplySchemaUpdate(context.Background(), d, SchemaUpdateOptions{Host: "h", By: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	if len(up.Applied) != 2 {
		t.Fatalf("the update applied %v, want the two index migrations and not 9001 again", up.Applied)
	}
	if pending, _ := PendingMigrations(d); len(pending) != 0 {
		t.Fatalf("still pending: %q", names(pending))
	}
}

// TestApplySchemaUpdateBuildsTheIndexAndRecordsIt: what the button and
// `unmask migrate` do.
func TestApplySchemaUpdateBuildsTheIndexAndRecordsIt(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	if _, err := MigrateWith(d, MigrateOptions{Defer: true, DeferOver: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, ok, err := d.LoadSchemaUpdate(ctx); err != nil || ok {
		t.Fatalf("record before any run = (%v, %v), want none", ok, err)
	}
	// A slow host, so that the build is one worth announcing.
	if err := d.SaveMaintState(ctx, MaintSchemaRate, SchemaRateRecord{MicrosPerRow: 20000, Rows: 500000}); err != nil {
		t.Fatal(err)
	}

	var lines []string
	res, err := ApplySchemaUpdate(ctx, d, SchemaUpdateOptions{Host: "host-a", By: "alice",
		Logf: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 2 {
		t.Fatalf("applied %v", res.Applied)
	}
	if !hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Fatal("index not built")
	}
	if got := d.EventJA4IndexHint(); got == "" {
		t.Error("hint still off after the update")
	}
	rec, ok, err := d.LoadSchemaUpdate(ctx)
	if err != nil || !ok {
		t.Fatalf("no record after the run (%v)", err)
	}
	if rec.State != SchemaUpdateDone || rec.By != "alice" || rec.Host != "host-a" || rec.PID != os.Getpid() {
		t.Errorf("record = %+v", rec)
	}
	if len(rec.Items) != 2 || rec.EndedAt == 0 || rec.Err != "" {
		t.Errorf("record = %+v", rec)
	}
	if len(lines) == 0 || !strings.Contains(lines[0], "0032_event_ja4_index") || !strings.Contains(lines[0], "estimated") {
		t.Errorf("the run must open with what it is about to build and for how long; it printed %q", lines)
	}
	if rec.EstHighSec <= 0 {
		t.Errorf("the record carries no estimate: %+v", rec)
	}
	// Nothing pending: a second run is a no-op and leaves the record alone.
	res, err = ApplySchemaUpdate(ctx, d, SchemaUpdateOptions{Host: "host-a", By: "bob"})
	if err != nil || len(res.Applied) != 0 {
		t.Fatalf("second run = (%v, %v)", res.Applied, err)
	}
	if rec2, _, _ := d.LoadSchemaUpdate(ctx); rec2.By != "alice" {
		t.Errorf("a run with nothing to do rewrote the record: %+v", rec2)
	}
}

// TestApplySchemaUpdateRefusesASecondRun: two builds of the same index would
// queue on the write lock, and the second would find the migration applied
// under it.  A run that is going is left to finish; one whose process is gone
// does not block the next.
func TestApplySchemaUpdateRefusesASecondRun(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	ctx := context.Background()

	// Another run: its record, and the lock it holds while it runs.
	other, err := d.LockSchemaRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SaveMaintState(ctx, MaintSchemaUpdate, SchemaUpdateRecord{
		State: SchemaUpdateRunning, Host: "host-a", PID: 4242, By: "alice", StartedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	_, err = ApplySchemaUpdate(ctx, d, SchemaUpdateOptions{Host: "host-a", By: "bob"})
	if !errors.Is(err, ErrSchemaUpdateRunning) || !strings.Contains(err.Error(), "by alice") {
		t.Fatalf("err = %v, want ErrSchemaUpdateRunning naming the other run", err)
	}
	if hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Fatal("the refused run built the index")
	}

	// Its process is gone, and the lock with it: the next run goes ahead,
	// whatever the record still says.
	other.Release()
	if _, err := ApplySchemaUpdate(ctx, d, SchemaUpdateOptions{Host: "host-a", By: "bob"}); err != nil {
		t.Fatalf("the earlier run's lock is free; the next must go ahead: %v", err)
	}
	if !hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Fatal("index not built")
	}
}

// TestApplySchemaUpdateCancelled: a cancelled build leaves no index, no
// recorded version and a record that says so -- the state before the run,
// with nothing for the operator to clean up.
func TestApplySchemaUpdateCancelled(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	ctx, cancel := context.WithCancel(context.Background())
	// The cancel arrives once the run has started: its record is written,
	// the first migration is about to be applied.
	beforeApply = func(string) { cancel() }
	defer func() { beforeApply = nil }()

	_, err := ApplySchemaUpdate(ctx, d, SchemaUpdateOptions{Host: "h", By: "cli"})
	beforeApply = nil
	if err == nil {
		t.Fatal("a cancelled run returned no error")
	}
	if hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Fatal("a cancelled run left the index behind")
	}
	if pending, _ := PendingMigrations(d); len(pending) != 2 {
		t.Fatalf("pending after cancel = %q, want both", names(pending))
	}
	rec, ok, err := d.LoadSchemaUpdate(context.Background())
	if err != nil || !ok || rec.State != SchemaUpdateCancelled {
		t.Fatalf("record = (%+v, %v, %v), want cancelled", rec, ok, err)
	}
	if d.SchemaUpdateAlive(context.Background(), rec, time.Now()) {
		t.Error("a cancelled run reads as still running")
	}
	// And it can simply be run again.
	if _, err := ApplySchemaUpdate(context.Background(), d, SchemaUpdateOptions{Host: "h", By: "cli"}); err != nil {
		t.Fatal(err)
	}
	if !hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Fatal("index not built by the run after the cancelled one")
	}
}

// TestCancelInterruptsARunningBuild: the cancel has to reach a statement
// that is already running -- that is when an operator presses it.  The build
// is over a table large enough to still be going when the cancel lands; on a
// machine fast enough to finish first there is nothing to observe, and the
// test says so instead of failing.
func TestCancelInterruptsARunningBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a large table")
	}
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 0)
	// One statement fills the table: row by row through the driver is where
	// the time goes, under the race detector above all.
	if _, err := d.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 25000)
		INSERT INTO unmask_event (site, host, ip_address, ja4, phase, date_created)
		SELECT 's', 'h', X'0A000001', 't13d' || (i % 977), 'serve', CURRENT_TIMESTAMP FROM n`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	beforeApply = func(string) {
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
	}
	defer func() { beforeApply = nil }()

	t0 := time.Now()
	_, err := ApplySchemaUpdate(ctx, d, SchemaUpdateOptions{Host: "h", By: "cli"})
	beforeApply = nil
	took := time.Since(t0)
	if err == nil {
		t.Skipf("the build finished in %v, before the cancel landed", took)
	}
	if hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Fatal("the interrupted build left its index behind")
	}
	rec, _, _ := d.LoadSchemaUpdate(context.Background())
	if rec.State != SchemaUpdateCancelled {
		t.Fatalf("record state = %q, want cancelled (err: %v)", rec.State, err)
	}
	// The table is still whole and writable.
	if _, err := d.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created)
		VALUES ('s','h', X'0A000002', 'serve', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("write after an interrupted build: %v", err)
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil || n != 25001 {
		t.Fatalf("rows after an interrupted build = %d (%v), want all 25001", n, err)
	}
	t.Logf("interrupted after %v", took)
}

// TestSchemaUpdateAlive: a run is going when its record says so and its lock
// is held -- nothing about its process, its host id or its age counts.  Every
// one of those misled once: a daemon restarted into the id of the run it
// outlived counted as that run, a process the daemon's unit cannot look at
// counted as alive, and a run cut short by a container re-create (a new host
// id) held the new daemon's writes for an hour.
func TestSchemaUpdateAlive(t *testing.T) {
	d := migratedDB(t)
	ctx := context.Background()
	now := time.Now()
	running := SchemaUpdateRecord{State: SchemaUpdateRunning, Host: "a", PID: os.Getpid(), StartedAt: now.Unix()}

	if d.SchemaUpdateAlive(ctx, running, now) {
		t.Error("record says running, no run has ever locked: counted as going")
	}
	lock, err := d.LockSchemaRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !d.SchemaUpdateAlive(ctx, running, now) {
		t.Error("record says running, lock held: not counted as going")
	}
	for name, rec := range map[string]SchemaUpdateRecord{
		"another host id":            {State: SchemaUpdateRunning, Host: "0123456789ab", PID: 57, StartedAt: now.Add(-3 * time.Minute).Unix()},
		"a process id not seen here": {State: SchemaUpdateRunning, Host: "a", PID: 1 << 30, StartedAt: now.Unix()},
	} {
		if !d.SchemaUpdateAlive(ctx, rec, now) {
			t.Errorf("%s, lock held: not counted as going", name)
		}
	}
	if d.SchemaUpdateAlive(ctx, SchemaUpdateRecord{State: SchemaUpdateDone, Host: "a"}, now) {
		t.Error("a record that says done, lock held: counted as going")
	}
	lock.Release()
	lock.Release() // twice is harmless
	for name, rec := range map[string]SchemaUpdateRecord{
		"this host, this process's id":  running,
		"another host id, a minute old": {State: SchemaUpdateRunning, Host: "0123456789ab", PID: 57, StartedAt: now.Add(-time.Minute).Unix()},
	} {
		if d.SchemaUpdateAlive(ctx, rec, now) {
			t.Errorf("%s, lock free: counted as going", name)
		}
	}
}

// TestSchemaRunLockKeepsRunsApart: one run at a time, however they are
// started; a look at the lock (the daemon's, every few seconds) takes it for
// an instant and must not turn a run away; and it goes with its holder.
func TestSchemaRunLockKeepsRunsApart(t *testing.T) {
	d := migratedDB(t)
	ctx := context.Background()
	first, err := d.LockSchemaRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.LockSchemaRun(ctx); !errors.Is(err, ErrSchemaUpdateRunning) {
		t.Fatalf("a second run while the first holds the lock: %v, want ErrSchemaUpdateRunning", err)
	}
	if held, known := d.SchemaRunLockHeld(ctx); !held || !known {
		t.Errorf("held = %v, known = %v; want the lock seen as held", held, known)
	}
	first.Release()
	if held, known := d.SchemaRunLockHeld(ctx); held || !known {
		t.Errorf("after release: held = %v, known = %v", held, known)
	}

	// Looks at the lock all the time, while a run starts: it must get it.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				d.SchemaRunLockHeld(ctx)
			}
		}
	}()
	for i := 0; i < 50; i++ {
		l, err := d.LockSchemaRun(ctx)
		if err != nil {
			close(stop)
			<-done
			t.Fatalf("a run starting while the lock is looked at: %v", err)
		}
		l.Release()
	}
	close(stop)
	<-done
}

// TestSchemaRunLockOnAFileItCannotWrite: a lock file left by another user --
// `unmask migrate` run as root with its privileges kept -- does not turn the
// daemon's runs away: the lock is taken on it read-only, and still keeps two
// runs apart.
func TestSchemaRunLockOnAFileItCannotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write any file")
	}
	d := migratedDB(t)
	ctx := context.Background()
	if err := os.WriteFile(d.schemaRunLockPath(), nil, 0o444); err != nil {
		t.Fatal(err)
	}
	first, err := d.LockSchemaRun(ctx)
	if err != nil {
		t.Fatalf("a run with a lock file it cannot write: %v", err)
	}
	defer first.Release()
	if _, err := d.LockSchemaRun(ctx); !errors.Is(err, ErrSchemaUpdateRunning) {
		t.Errorf("a second run: %v, want ErrSchemaUpdateRunning", err)
	}
	if held, known := d.SchemaRunLockHeld(ctx); !held || !known {
		t.Errorf("held = %v, known = %v; want the lock seen as held", held, known)
	}
}

// TestSchemaRunLockFileNotCreatedByALook: looking does not create the lock
// file (a new install's doctor, the daemon's watch).
func TestSchemaRunLockFileNotCreatedByALook(t *testing.T) {
	d := migratedDB(t)
	if held, known := d.SchemaRunLockHeld(context.Background()); held || !known {
		t.Fatalf("held = %v, known = %v on a database no run has touched", held, known)
	}
	if _, err := os.Stat(d.SQLitePath + ".schema-update.lock"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a look created the lock file (%v)", err)
	}
}

// TestApplySchemaUpdateRecordsARefusal: a run that stops before it builds --
// short of space -- says so in its record, where the admin UI reads it; a run
// started from the button has nobody reading its terminal.
func TestApplySchemaUpdateRecordsARefusal(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	prev := dirFree
	dirFree = func(string) (int64, error) { return 1 << 10, nil }
	defer func() { dirFree = prev }()
	_, err := ApplySchemaUpdate(context.Background(), d, SchemaUpdateOptions{Host: "h", By: "alice"})
	if err == nil || !strings.Contains(err.Error(), "free") {
		t.Fatalf("err = %v, want the space refusal", err)
	}
	rec, ok, err := d.LoadSchemaUpdate(context.Background())
	if err != nil || !ok || rec.State != SchemaUpdateFailed || !strings.Contains(rec.Err, "skip-space-check") || rec.By != "alice" {
		t.Fatalf("record = %+v (ok %v, err %v), want failed with the reason", rec, ok, err)
	}
	if hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Error("the refused run built the index")
	}
	if held, _ := d.SchemaRunLockHeld(context.Background()); held {
		t.Error("the refused run left its lock held")
	}
}

// TestApplySchemaUpdateFinishesBeforeDone: what follows the builds writes to
// the database (the verdict-id backfill), so it runs while the record still
// says running and the lock is still held -- the daemon holds its writers back
// until then.  Its failure is reported, the update is still done.
func TestApplySchemaUpdateFinishesBeforeDone(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 400)
	ctx := context.Background()
	var during SchemaUpdateRecord
	var heldDuring bool
	res, err := ApplySchemaUpdate(ctx, d, SchemaUpdateOptions{Host: "h", By: "cli", Finish: func(context.Context) error {
		during, _, _ = d.LoadSchemaUpdate(ctx)
		heldDuring, _ = d.SchemaRunLockHeld(ctx)
		return errors.New("backfill: no such thing")
	}})
	if err != nil {
		t.Fatal(err)
	}
	if during.State != SchemaUpdateRunning || !heldDuring {
		t.Errorf("during Finish: record %q, lock held %v; want running and held", during.State, heldDuring)
	}
	if res.FinishErr == nil || !strings.Contains(res.FinishErr.Error(), "backfill") {
		t.Errorf("FinishErr = %v", res.FinishErr)
	}
	rec, _, _ := d.LoadSchemaUpdate(ctx)
	if rec.State != SchemaUpdateDone {
		t.Errorf("record after = %q, want done (the schema is applied)", rec.State)
	}
}

// TestPendingMigrationsChangesNothing: the daemon asks every few seconds while
// an update waits, and -status, -notice and doctor promise to change nothing.
// It used to create the version table and its baseline row first.
func TestPendingMigrationsChangesNothing(t *testing.T) {
	d := migratedDB(t)
	if _, err := d.Exec(`DROP TABLE schema_migrations`); err != nil {
		t.Fatal(err)
	}
	pending, err := PendingMigrations(d)
	if err != nil {
		t.Fatal(err)
	}
	if has, _ := hasTable(d, "schema_migrations"); has {
		t.Error("reading what is pending created the version table")
	}
	// What a pass would see: the baseline counted, everything after pending.
	for _, m := range pending {
		if m.Version == 1 {
			t.Error("the baseline is reported pending; a pass records it without applying anything")
		}
	}
	if len(pending) == 0 {
		t.Error("nothing pending on a database with no versions recorded")
	}
}

// TestHostRateReplacesTheBuiltInRange: the built-in range has to cover every
// disk there is, so it is wide.  A host that has built an index knows its own
// rate, and its next estimate is made from that.
func TestHostRateReplacesTheBuiltInRange(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 1000)
	builtin, err := PendingMigrations(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SaveMaintState(context.Background(), MaintSchemaRate,
		SchemaRateRecord{MicrosPerRow: 1000, Rows: 500000, MeasuredAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	measured, err := PendingMigrations(d)
	if err != nil {
		t.Fatal(err)
	}
	// 1000 rows at 1000 microseconds each is one second, with room either side.
	if lo, hi := measured[0].EstLow, measured[0].EstHigh; lo != 700*time.Millisecond || hi != 1500*time.Millisecond {
		t.Errorf("estimate from the host's rate = %v..%v, want 700ms..1.5s", lo, hi)
	}
	if measured[0].EstHigh == builtin[0].EstHigh {
		t.Error("the recorded rate changed nothing")
	}
}

func TestEstimateRange(t *testing.T) {
	for _, c := range []struct {
		lo, hi time.Duration
		want   string
	}{
		{0, 0, "no time"},
		{time.Second, 3 * time.Second, "under 10 s"},
		{12 * time.Second, 36 * time.Second, "20-40 s"},
		{25 * time.Second, 28 * time.Second, "about 30 s"},
		{70 * time.Second, 210 * time.Second, "2-4 min"},
		{4 * time.Minute, 10 * time.Minute, "4-10 min"},
		{9*time.Minute + time.Second, 10 * time.Minute, "about 10 min"},
	} {
		if got := EstimateRange(c.lo, c.hi); got != c.want {
			t.Errorf("EstimateRange(%v, %v) = %q, want %q", c.lo, c.hi, got, c.want)
		}
	}
}

// TestApplySchemaUpdateOnANewDatabase: `unmask migrate` is also how a database
// is created.  The run's record lives in a table one of the migrations
// creates, so on a new database the run has to start without it -- it used to
// stop at "no such table" with the schema half made.
func TestApplySchemaUpdateOnANewDatabase(t *testing.T) {
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if has, err := HasSchema(d); err != nil || has {
		t.Fatalf("HasSchema on a new database = (%v, %v)", has, err)
	}
	var lines []string
	res, err := ApplySchemaUpdate(context.Background(), d, SchemaUpdateOptions{Host: "h", By: "cli",
		Logf: func(f string, a ...any) { lines = append(lines, f) }})
	if err != nil {
		t.Fatalf("creating the schema: %v", err)
	}
	if len(res.Applied) == 0 {
		t.Fatal("nothing applied on a new database")
	}
	if pending, err := PendingMigrations(d); err != nil || len(pending) != 0 {
		t.Fatalf("pending after creating the schema = (%q, %v)", names(pending), err)
	}
	if !hasIndexNow(t, d, "idx_unmask_event_ja4_phase") {
		t.Error("the fingerprint index is missing on a new database")
	}
	if rec, ok, err := d.LoadSchemaUpdate(context.Background()); err != nil || !ok || rec.State != SchemaUpdateDone {
		t.Errorf("record = (%+v, %v, %v), want a finished run", rec, ok, err)
	}
	// Nothing on a new database takes long enough to be announced.
	if len(lines) != 0 {
		t.Errorf("a new database printed a plan: %q", lines)
	}
	// The same as what Migrate makes.
	ref := migratedDB(t)
	for _, q := range []string{
		`SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%'`,
		`SELECT COUNT(*) FROM schema_migrations`,
	} {
		var a, b int
		if err := d.QueryRow(q).Scan(&a); err != nil {
			t.Fatal(err)
		}
		if err := ref.QueryRow(q).Scan(&b); err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Errorf("%s: %d via the schema update, %d via Migrate", q, a, b)
		}
	}
}
