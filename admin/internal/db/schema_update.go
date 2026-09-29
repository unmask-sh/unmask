package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// A schema update is the application of whatever migrations are pending,
// including the index builds the daemon left for the operator at startup (see
// the package doc of migrator.go).  It is run by `unmask migrate` -- from a
// shell, or started by the daemon as a child process when an administrator
// presses the button -- and it leaves a record (MaintSchemaUpdate) the daemon,
// doctor and the admin UI read to say what is going on.
//
// One process, not the daemon itself: an index build over a large table is
// minutes of sorting, and a run that dies or is killed must not take the
// challenge down with it.

// SchemaUpdateOptions tunes ApplySchemaUpdate.
type SchemaUpdateOptions struct {
	// Host identifies this machine in the record (the daemon's host id).
	Host string
	// By is who started the run: an administrator's username, or
	// SchemaUpdateByCLI.
	By string
	// Logf receives the plan and the progress lines.  nil discards them.
	Logf func(format string, args ...any)
	// SkipSpaceCheck runs even when the free space next to the database looks
	// short for the indexes to build.
	SkipSpaceCheck bool
}

// SchemaUpdateResult is what a run did.
type SchemaUpdateResult struct {
	Applied []AppliedMigration
	Elapsed time.Duration
}

// SchemaUpdateHoldsWrites reports whether a schema update on this database
// keeps every other write out while it runs.  SQLite has one writer, and the
// run holds it for the whole of an index build; MariaDB builds an index online
// and holds nothing.  What is said about a run -- the admin UI's notice, the
// lines a package upgrade prints -- follows it.
func (d *DB) SchemaUpdateHoldsWrites() bool { return d != nil && d.Driver == DriverSQLite }

// SchemaUpdateByCLI is who a run started from a shell is recorded as (the
// default of `unmask migrate -by`).
const SchemaUpdateByCLI = "cli"

// ErrSchemaUpdateRunning: another run is going.
var ErrSchemaUpdateRunning = errors.New("a schema update is already running")

// indexBytesPerRow sizes an index for the free-space check: the key columns
// of the widest index a deferrable migration builds today, the rowid and the
// page overhead, rounded up.
const indexBytesPerRow = 120

// rateMinRows: a build over fewer rows than this measures the fixed costs, not
// the rate, and is not recorded as this host's.
const rateMinRows = 100000

// Alive reports whether the run the record describes is still going, as far
// as can be told from here.  On the host that started it that is whether the
// process exists; from another host (a shared database) it is whether the run
// is young enough to believe.
func (r SchemaUpdateRecord) Alive(host string, now time.Time) bool {
	if r.State != SchemaUpdateRunning {
		return false
	}
	if r.Host == host {
		return processAlive(r.PID)
	}
	limit := 3 * time.Duration(r.EstHighSec) * time.Second
	if limit < time.Hour {
		limit = time.Hour
	}
	return now.Sub(time.Unix(r.StartedAt, 0)) < limit
}

// processAlive: a process with this id exists and is an unmask.  The name is
// checked because a process id is reused: long after a run was killed its
// number may belong to something else.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		// No /proc to look in: the signal said it exists, believe that.
		return true
	}
	for _, name := range runnerNames {
		if bytes.Contains(cmdline, []byte(name)) {
			return true
		}
	}
	return false
}

// checkpointAfterBuild moves a newly built index out of the write-ahead log.
//
// The index is written to the log and stays there until a checkpoint copies
// it into the database file -- a copy as large as the index.  Left alone, that
// copy lands on whichever of the daemon's writes crosses the auto-checkpoint
// threshold next, and a visitor's event waits for it.
//
// PASSIVE does the copying and waits for nobody.  The modes that also shrink
// the file wait until no reader is left on the log, and the daemon always has
// readers: a TRUNCATE here once stood behind a long dashboard read until its
// deadline, with the daemon's writers held off for all of it.  So the file is
// shrunk only if that takes no waiting; otherwise it stays large until the
// daemon's own trim (its write-ahead log watch) gets to it, which costs disk
// space and nothing else.
func checkpointAfterBuild(conn *DB, logf func(string, ...any)) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cp, err := conn.CheckpointWAL(ctx, "PASSIVE", 0)
	if err != nil {
		logf("write-ahead log checkpoint: %v (the daemon's next checkpoint does it)", err)
		return
	}
	if cp.Busy || cp.Checkpointed < cp.LogFrames {
		// A reader holds an older snapshot: what it still needs stays in
		// the log, and the next checkpoint takes it.
		return
	}
	if _, err := conn.CheckpointWAL(ctx, "TRUNCATE", time.Second); err != nil {
		logf("write-ahead log truncate: %v (the file stays large until the daemon trims it)", err)
	}
}

// beforeApply, when set, is called before each migration of a schema update
// is applied.  Tests use it to act at that moment; nil otherwise.
var beforeApply func(name string)

// runnerNames is what the command line of a process running a schema update
// contains.  A variable so a test, whose process is named after the test
// binary, can add its own.
var runnerNames = []string{"unmask"}

// AddRunnerNameForTest makes Alive accept a process whose command line
// contains name.  For the tests of other packages, whose stand-in for
// `unmask migrate` is the test binary itself.
func AddRunnerNameForTest(name string) { runnerNames = append(runnerNames, name) }

// LoadSchemaUpdate reads the last run's record.  ok is false when there has
// never been one (or the table that holds it does not exist yet).
func (d *DB) LoadSchemaUpdate(ctx context.Context) (rec SchemaUpdateRecord, ok bool, err error) {
	has, err := hasTable(d, "unmask_maint_state")
	if err != nil || !has {
		return rec, false, err
	}
	ok, err = d.LoadMaintState(ctx, MaintSchemaUpdate, &rec)
	return rec, ok, err
}

// ApplySchemaUpdate applies every pending migration and keeps the record.
//
// ctx cancels it: a cancelled index build is rolled back by SQLite (DDL is
// transactional there), the migration stays pending and the record reads
// "cancelled".
func ApplySchemaUpdate(ctx context.Context, conn *DB, opt SchemaUpdateOptions) (SchemaUpdateResult, error) {
	var res SchemaUpdateResult
	logf := func(format string, args ...any) {
		if opt.Logf != nil {
			opt.Logf(format, args...)
		}
	}
	// The base schema first: the record lives in a table it creates.
	if err := migrateBase(conn); err != nil {
		return res, err
	}
	pending, err := pendingMigrations(conn)
	if err != nil {
		return res, err
	}
	if len(pending) == 0 {
		return res, nil
	}
	if prev, ok, err := conn.LoadSchemaUpdate(ctx); err == nil && ok && prev.Alive(opt.Host, time.Now()) && prev.PID != os.Getpid() {
		return res, fmt.Errorf("%w (started %s by %s on %s, pid %d)", ErrSchemaUpdateRunning,
			time.Unix(prev.StartedAt, 0).UTC().Format("2006-01-02 15:04 UTC"), prev.By, prev.Host, prev.PID)
	}

	rec := SchemaUpdateRecord{
		State: SchemaUpdateRunning, Host: opt.Host, PID: os.Getpid(), By: opt.By,
		StartedAt: time.Now().Unix(),
	}
	var low, high time.Duration
	var buildRows int64 // rows x indexes to build, for the rate
	for _, m := range pending {
		rec.Items = append(rec.Items, m.Name)
		low, high = low+m.EstLow, high+m.EstHigh
		buildRows += m.Rows * int64(len(m.Indexes))
		// The plan names what takes time.  A new install applies every
		// migration there is, each in a moment, and has nothing to be told.
		if len(m.Indexes) > 0 && m.EstHigh >= time.Second {
			logf("%s: %s", m.Name, m.describe())
		}
	}
	rec.EstLowSec, rec.EstHighSec = int(low.Seconds()), int(high.Seconds())

	if buildRows > 0 && conn.Driver == DriverSQLite && conn.SQLitePath != "" && !opt.SkipSpaceCheck {
		// The index, the same again in the write-ahead log until it is
		// checkpointed, and the sort's temporary files: all next to the
		// database.
		need := buildRows * indexBytesPerRow * 3
		dir := filepath.Dir(conn.SQLitePath)
		if free, err := DirFree(dir); err == nil && free < need {
			return res, fmt.Errorf("the index build needs about %d MB free in %s and %d MB is available; free some space, or pass -skip-space-check to go ahead anyway",
				need>>20, dir, free>>20)
		}
	}
	// The record lives in a table that a migration creates (0031).  A
	// database from before it -- a new one above all -- has nowhere to keep
	// the record until that migration has run, so the run starts without one
	// and writes it as soon as it can.  Nothing is lost by that: what runs
	// before 0031 is never an index build.
	recorded := false
	record := func(c context.Context) error {
		if has, err := hasTable(conn, "unmask_maint_state"); err != nil || !has {
			return err
		}
		if err := conn.SaveMaintState(c, MaintSchemaUpdate, rec); err != nil {
			return err
		}
		recorded = true
		return nil
	}
	if err := record(ctx); err != nil {
		return res, fmt.Errorf("record the run: %w", err)
	}

	t0 := time.Now()
	var buildTime time.Duration
	var runErr error
	for _, m := range pending {
		if !recorded {
			if err := record(ctx); err != nil {
				runErr = fmt.Errorf("record the run: %w", err)
				break
			}
		}
		if beforeApply != nil {
			beforeApply(m.Name)
		}
		elapsed, err := applyMigration(conn, m, MigrateOptions{Logf: opt.Logf, ctx: ctx})
		if err != nil {
			runErr = err
			break
		}
		res.Applied = append(res.Applied, AppliedMigration{Name: m.Name, Elapsed: elapsed})
		if len(m.Indexes) > 0 {
			buildTime += elapsed
		}
	}
	res.Elapsed = time.Since(t0)

	rec.EndedAt, rec.Seconds = time.Now().Unix(), res.Elapsed.Seconds()
	switch {
	case runErr == nil:
		rec.State = SchemaUpdateDone
	case ctx.Err() != nil:
		rec.State, rec.Err = SchemaUpdateCancelled, "cancelled"
	default:
		rec.State, rec.Err = SchemaUpdateFailed, runErr.Error()
	}
	// The record outlives the run's context: a cancelled run still has to say
	// it was cancelled.
	wctx, wcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer wcancel()
	if err := record(wctx); err != nil {
		logf("could not record how the run ended: %v", err)
	}
	if runErr == nil && buildRows >= rateMinRows && buildTime > 0 {
		rate := SchemaRateRecord{
			MicrosPerRow: float64(buildTime.Microseconds()) / float64(buildRows),
			Rows:         buildRows, MeasuredAt: time.Now().Unix(),
		}
		if err := conn.SaveMaintState(wctx, MaintSchemaRate, rate); err != nil {
			logf("could not record this host's build rate: %v", err)
		}
	}
	if conn.Driver == DriverSQLite && buildRows > 0 && len(res.Applied) > 0 {
		checkpointAfterBuild(conn, logf)
	}
	ictx, icancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer icancel()
	if err := conn.RefreshIndexes(ictx); err != nil {
		logf("could not re-read the index list: %v", err)
	}
	if runErr != nil && ctx.Err() != nil {
		return res, fmt.Errorf("cancelled: %w", ctx.Err())
	}
	return res, runErr
}
