package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// Finish runs once every migration has been applied, before the run is
	// recorded as done: the work that follows a schema update and writes to
	// the database (`unmask migrate` gathers the planner's statistics on a
	// small database).  Until the record says done the daemon holds its
	// writers back, so they do not meet it on the lock -- which is why it
	// must stay short.  It gets the run's context: an interrupt stops it.
	// Its error is reported (FinishErr) without making the update a failure:
	// the schema is applied.
	Finish func(ctx context.Context) error
}

// SchemaUpdateResult is what a run did.
type SchemaUpdateResult struct {
	Applied []AppliedMigration
	Elapsed time.Duration
	// FinishErr is what SchemaUpdateOptions.Finish returned.
	FinishErr error
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

// schemaRecordTimeout bounds each write of the run's record after the work: a
// fresh deadline for each, taken out when the write is made.  A variable for
// the test that proves the end of a run is recorded after a long Finish.
var schemaRecordTimeout = 30 * time.Second

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
func checkpointAfterBuild(parent context.Context, conn *DB, logf func(string, ...any)) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
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

// dirFree is DirFree, for the space check; tests put a full disk in its place.
var dirFree = DirFree

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
// It holds the run lock (LockSchemaRun) from before the record is written
// until the record says how the run ended: that is what tells the daemon, and
// any other run, that this one is going.
//
// ctx cancels it: a cancelled index build is rolled back by SQLite (DDL is
// transactional there) and killed on the server by MariaDB, the migration
// stays pending and the record reads "cancelled".
func ApplySchemaUpdate(ctx context.Context, conn *DB, opt SchemaUpdateOptions) (SchemaUpdateResult, error) {
	var res SchemaUpdateResult
	logf := func(format string, args ...any) {
		if opt.Logf != nil {
			opt.Logf(format, args...)
		}
	}
	finish := func() {
		if opt.Finish == nil {
			return
		}
		if err := opt.Finish(ctx); err != nil {
			res.FinishErr = err
			logf("after the update: %v", err)
		}
	}
	// The base schema first: the record lives in a table it creates.
	if err := migrateBase(conn); err != nil {
		return res, err
	}
	pending, err := pendingMigrations(conn, false)
	if err != nil {
		return res, err
	}
	if len(pending) == 0 {
		finish()
		return res, nil
	}
	lock, err := conn.LockSchemaRun(ctx)
	if err != nil {
		if errors.Is(err, ErrSchemaUpdateRunning) {
			if prev, ok, lerr := conn.LoadSchemaUpdate(ctx); lerr == nil && ok && prev.State == SchemaUpdateRunning {
				return res, fmt.Errorf("%w (started %s by %s on %s, pid %d)", ErrSchemaUpdateRunning,
					time.Unix(prev.StartedAt, 0).UTC().Format("2006-01-02 15:04 UTC"), prev.By, prev.Host, prev.PID)
			}
		}
		return res, err
	}
	defer lock.Release()
	// A compaction holds the same write lock for as long as it runs (vacuum.go);
	// the two would only fail each other.  Its run looks for this one too.
	if held, _ := conn.VacuumRunLockHeld(); held {
		return res, ErrVacuumRunning
	}
	// Another run may have applied them while this one waited for the lock.
	if pending, err = pendingMigrations(conn, false); err != nil {
		return res, err
	}
	if len(pending) == 0 {
		finish()
		return res, nil
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
	if buildRows > 0 && conn.Driver == DriverSQLite && conn.SQLitePath != "" && !opt.SkipSpaceCheck {
		// The index, the same again in the write-ahead log until it is
		// checkpointed, and the sort's temporary files: all next to the
		// database.  Checked once the run is on record, so that a refusal
		// is on record too: a run started from the admin UI has nobody
		// reading its terminal.
		need := buildRows * indexBytesPerRow * 3
		dir := filepath.Dir(conn.SQLitePath)
		if free, err := dirFree(dir); err == nil && free < need {
			runErr = fmt.Errorf("the index build needs about %d MB free in %s and %d MB is available; free some space, or run `unmask migrate -skip-space-check` to go ahead anyway",
				need>>20, dir, free>>20)
		}
	}
	// stage puts what the run is doing now on record, for the admin UI, and
	// says it on the terminal.  The run goes on if it cannot be recorded:
	// it is only the account of the run.
	stage := func(name, current string, done int, line string, args ...any) {
		rec.Stage, rec.Current, rec.Done, rec.StageAt = name, current, done, time.Now().Unix()
		if recorded {
			sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := record(sctx); err != nil {
				logf("could not record the run's progress: %v", err)
			}
			scancel()
		}
		if line != "" {
			logf(line, args...)
		}
	}
	announced := false // a build the terminal was told about
	for i, m := range pending {
		if runErr != nil {
			break
		}
		if !recorded {
			if err := record(ctx); err != nil {
				runErr = fmt.Errorf("record the run: %w", err)
				break
			}
		}
		if beforeApply != nil {
			beforeApply(m.Name)
		}
		// The terminal hears about what takes time, as the plan above: a
		// new install's index migrations are each over in a moment.
		says := len(m.Indexes) > 0 && m.EstHigh >= time.Second
		announced = announced || says
		if says {
			stage(SchemaStageIndex, m.Name, i, "%s: building (%d of %d)", m.Name, i+1, len(pending))
		} else {
			stage(SchemaStageIndex, m.Name, i, "")
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
		if says {
			logf("%s: built in %s", m.Name, elapsed.Round(time.Second))
		}
	}
	res.Elapsed = time.Since(t0)

	if runErr == nil && buildRows >= rateMinRows && buildTime > 0 {
		rate := SchemaRateRecord{
			MicrosPerRow: float64(buildTime.Microseconds()) / float64(buildRows),
			Rows:         buildRows, MeasuredAt: time.Now().Unix(),
		}
		rctx, rcancel := context.WithTimeout(context.Background(), schemaRecordTimeout)
		if err := conn.SaveMaintState(rctx, MaintSchemaRate, rate); err != nil {
			logf("could not record this host's build rate: %v", err)
		}
		rcancel()
	}
	// The new index sits in the write-ahead log until a checkpoint copies it
	// into the database file; done here, the copy does not land on a
	// visitor's event.  An interrupt stops it as it stops the build: the log
	// keeps what was not copied, for the daemon's own checkpoint.
	if conn.Driver == DriverSQLite && buildRows > 0 && len(res.Applied) > 0 {
		line := ""
		if announced {
			line = "moving the new index out of the write-ahead log"
		}
		stage(SchemaStageCheckpoint, "", len(res.Applied), line)
		checkpointAfterBuild(ctx, conn, logf)
	}
	// What follows the builds writes too, so it comes before the record says
	// done (see SchemaUpdateOptions.Finish), and it is stopped by the same
	// interrupt as the build.
	if runErr == nil && opt.Finish != nil {
		stage(SchemaStageFinish, "", len(res.Applied), "")
		finish()
	}

	rec.EndedAt, rec.Seconds = time.Now().Unix(), time.Since(t0).Seconds()
	switch {
	case runErr == nil:
		rec.State = SchemaUpdateDone
	case ctx.Err() != nil:
		rec.State, rec.Err = SchemaUpdateCancelled, "cancelled"
	default:
		rec.State, rec.Err = SchemaUpdateFailed, runErr.Error()
	}
	// The record outlives the run's context: a cancelled run still has to
	// say it was cancelled.  Its deadline starts now, not before the work
	// above: one taken out before it once expired while that work ran, and
	// left a finished run on record as running (2026-10-06).  The daemon may
	// be writing out what it kept during the run, so a busy database gets a
	// second and a third try.
	var endErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Second)
		}
		ectx, ecancel := context.WithTimeout(context.Background(), schemaRecordTimeout)
		endErr = record(ectx)
		ecancel()
		if endErr == nil {
			break
		}
	}
	if endErr != nil {
		logf("could not record how the run ended: %v", endErr)
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
