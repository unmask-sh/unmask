package db

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Compaction of a SQLite database: VACUUM, run while the daemon keeps serving.
//
// VACUUM writes every table and index into a new file in order and copies it
// back over the database.  The pages the retention prune freed go back to the
// filesystem, and a table whose pages were scattered across the file -- the
// state a large, long-pruned database is in -- is laid out in one run again,
// so a full scan reads the disk in order instead of seeking for every page.
//
// It holds SQLite's write lock from start to end, which on a large file is
// tens of minutes, and every other write meanwhile waits out the busy timeout
// and fails.  Readers carry on: the database is in WAL mode, and they read the
// pages as they were until the copy is committed.  So a compaction runs the
// way a schema update does (schema_update.go): as a process of its own
// (`unmask db-vacuum`), holding a run lock the daemon watches, while the
// daemon holds its writers back (DB.HoldWrites) -- the events, the access-log
// counters, the automatic bans and the audit rows wait in memory and are
// written when it ends.  The challenge is served throughout.
//
// What a run needs, measured on a fragmented events database with this
// driver (2026-09-30):
//
//   - disk: the copy (about the live data) and then the same again in the
//     write-ahead log while it is copied back -- 2.0 to 2.2 times the live
//     data, given back at the end (VacuumDiskNeed);
//   - memory in the run's process: its page cache and the driver, about 180
//     MB with the 16 MB cache it sets, whatever the size of the database;
//   - memory in the daemon: about 1 KB per held event, plus the access-log
//     counters, which are bounded (HeldEventsLimit);
//   - time: 46 to 87 s per GB of live data on a local SSD, several times
//     that on a slow disk (PlanVacuum's estimate).
//
// It can be stopped at any point: VACUUM is one transaction, and SQLite rolls
// a cancelled one back -- the database is as it was, the temporary copy gone.

// MaintVacuum is the task name a compaction run records under.
const MaintVacuum = "vacuum"

// MaintVacuumRate is the task name this host's measured compaction rate is
// kept under.
const MaintVacuumRate = "vacuum_rate"

// Compaction run states: the same words as a schema update's.
const (
	VacuumRunning   = "running"
	VacuumDone      = "done"
	VacuumFailed    = "failed"
	VacuumCancelled = "cancelled"
)

// VacuumByCLI is who a run started from a shell is recorded as.
const VacuumByCLI = "cli"

// VacuumRecord is the last compaction run: written before VACUUM starts (it
// holds the write lock while it runs, so there is no writing progress during
// it) and again when it ends.
type VacuumRecord struct {
	State string `json:"state"`
	// Host / PID: where it runs.  By: who started it -- an administrator's
	// username, or "cli".
	Host      string `json:"host,omitempty"`
	PID       int    `json:"pid,omitempty"`
	By        string `json:"by,omitempty"`
	StartedAt int64  `json:"started_at"`
	EndedAt   int64  `json:"ended_at,omitempty"`
	// EstLowSec / EstHighSec: the estimate shown when it started.
	EstLowSec  int `json:"est_low_s,omitempty"`
	EstHighSec int `json:"est_high_s,omitempty"`
	// FileBefore / LiveBefore: the file and the data in use when it started.
	// FileAfter: the file once it ended (done runs).
	FileBefore int64 `json:"file_before,omitempty"`
	LiveBefore int64 `json:"live_before,omitempty"`
	FileAfter  int64 `json:"file_after,omitempty"`
	// DiskFreeAtStart / WALAtStart: the free space in the database's directory
	// and the write-ahead log's size when it started -- what VacuumProgress
	// reads the run's own files against, since VACUUM's copy is a temporary
	// file that no directory listing shows.
	DiskFreeAtStart int64 `json:"disk_free_at_start,omitempty"`
	WALAtStart      int64 `json:"wal_at_start,omitempty"`
	// Seconds: how long it took (ended runs).
	Seconds float64 `json:"seconds,omitempty"`
	Err     string  `json:"err,omitempty"`
}

// VacuumRateRecord is how fast this host compacted its database the last time
// it did, per GB of live data.  Estimates use it in place of the derived
// range.
type VacuumRateRecord struct {
	SecondsPerGB float64 `json:"s_per_gb"`
	LiveBytes    int64   `json:"live_bytes"`
	MeasuredAt   int64   `json:"measured_at"`
}

// ErrVacuumRunning: another compaction is going.
var ErrVacuumRunning = errors.New("a database compaction is already running")

// ErrVacuumSQLiteOnly: compaction is a SQLite operation.  InnoDB reuses the
// space it frees and lays its pages out by itself.
var ErrVacuumSQLiteOnly = errors.New("compaction applies to SQLite only; MariaDB/MySQL reuses freed space on its own")

// vacuumRunLockPath is the lock a compaction run holds, next to the database.
func (d *DB) vacuumRunLockPath() string {
	if d == nil || d.Driver != DriverSQLite || d.SQLitePath == "" {
		return ""
	}
	return d.SQLitePath + ".vacuum.lock"
}

// LockVacuumRun takes the lock a compaction run holds while it runs.  It fails
// with ErrVacuumRunning when another run has it.
func (d *DB) LockVacuumRun(ctx context.Context) (*SchemaRunLock, error) {
	p := d.vacuumRunLockPath()
	if p == "" {
		return nil, ErrVacuumSQLiteOnly
	}
	return lockRunFile(ctx, p, ErrVacuumRunning)
}

// VacuumRunLockHeld reports whether a compaction run holds its lock now.
// known is false when that cannot be told.
func (d *DB) VacuumRunLockHeld() (held, known bool) {
	p := d.vacuumRunLockPath()
	if p == "" {
		return false, true
	}
	return runFileLockHeld(p)
}

// VacuumAlive reports whether the run rec describes is still going: it says
// it is, and its lock is held.
func (d *DB) VacuumAlive(rec VacuumRecord, now time.Time) bool {
	if rec.State != VacuumRunning {
		return false
	}
	if held, known := d.VacuumRunLockHeld(); known {
		return held
	}
	// The lock cannot be looked at: believe the record while it is young.
	limit := 3 * time.Duration(rec.EstHighSec) * time.Second
	if limit < time.Hour {
		limit = time.Hour
	}
	return now.Sub(time.Unix(rec.StartedAt, 0)) < limit
}

// LoadVacuum reads the last run's record.  ok is false when there has never
// been one.
func (d *DB) LoadVacuum(ctx context.Context) (rec VacuumRecord, ok bool, err error) {
	has, err := hasTable(d, "unmask_maint_state")
	if err != nil || !has {
		return rec, false, err
	}
	ok, err = d.LoadMaintState(ctx, MaintVacuum, &rec)
	return rec, ok, err
}

// The hand-over between a run and the daemon.
//
// A run must not take the write lock before the daemon has stopped writing:
// every write the daemon then tries waits out the busy timeout and fails.
// The daemon says it has stopped by writing the run's process id into a file
// next to the database; the run waits for that (a daemon that does not know
// about compaction runs never writes it, and the run refuses rather than
// fail the daemon's writes for its whole length).

// VacuumHeldPath is the hand-over file, "" without a database file.
func (d *DB) VacuumHeldPath() string {
	if d == nil || d.Driver != DriverSQLite || d.SQLitePath == "" {
		return ""
	}
	return d.SQLitePath + ".vacuum.held"
}

// WriteVacuumHeld says, for the run with process id pid, that this daemon has
// stopped writing.  Written to a temporary name and renamed, so the run never
// reads half of it.
func (d *DB) WriteVacuumHeld(pid int) error {
	p := d.VacuumHeldPath()
	if p == "" || pid <= 0 {
		return nil
	}
	tmp := p + ".tmp"
	body := fmt.Sprintf("run_pid=%d daemon_pid=%d at=%d\n", pid, os.Getpid(), time.Now().Unix())
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// VacuumHeldFor reports whether the daemon has said it stopped writing for
// the run with process id pid.
func (d *DB) VacuumHeldFor(pid int) bool {
	p := d.VacuumHeldPath()
	if p == "" {
		return false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(b)) {
		if v, ok := strings.CutPrefix(f, "run_pid="); ok {
			n, err := strconv.Atoi(v)
			return err == nil && n == pid
		}
	}
	return false
}

// Sizes the plan and the daemon's hold are worked out from.
const (
	// HeldEventBytes is what one event costs the daemon while it is held:
	// the event with its payload map, measured at 991 bytes on the event
	// mix of a busy site.
	HeldEventBytes = 1024
	// heldEventsFloor is the fewest events the daemon keeps while its
	// writes are held, whatever the memory: the bound a schema update's hold
	// had before compaction runs held for longer.
	heldEventsFloor = 50000
	// heldEventsMemShare: the daemon keeps held events up to this share of
	// the memory it may use (1/20 = 5%).
	heldEventsMemShare = 20
	// heldCountersBytes bounds the access-log counters the daemon keeps
	// while writes are held (nginxlog's per-address buckets are capped).
	heldCountersBytes = 64 << 20
)

// HeldEventsLimit is how many events the daemon keeps while its writes are
// held, before the oldest go: 5% of the memory it may use at about 1 KB each,
// and never fewer than 50,000.  The event flusher and PlanVacuum both use it.
func HeldEventsLimit() int {
	n := heldEventsFloor
	if mem := memLimitBytes(); mem > 0 {
		if m := int(mem / heldEventsMemShare / HeldEventBytes); m > n {
			n = m
		}
	}
	return n
}

// VacuumDiskNeed is the free space a compaction needs next to the database for
// live bytes of data: the copy, then the same again in the write-ahead log as
// it is copied back.  Measured at 2.0-2.2 times; asked at 2.2.
func VacuumDiskNeed(live int64) int64 { return live*2 + live/5 }

// Compaction time per GB of live data.
//
// Measured with this driver on a fragmented events database (a local SSD,
// the page cache dropped first): VACUUM ran 46 to 87 s per live GB, and the
// cold build of migration 0032's index on the same file 55 us per row.  A
// host that has built an index is estimated from its own rate through that
// ratio -- 0.84 to 1.58 s per GB for each us per row -- and a host that has
// compacted before, from its own compaction.
const (
	vacuumPerIndexRateLow  = 0.84
	vacuumPerIndexRateHigh = 1.58
	// vacuumMeasuredLow / High widen a measured rate into a range: the next
	// run meets a warmer or colder cache, a quieter or busier disk.
	vacuumMeasuredLow  = 0.8
	vacuumMeasuredHigh = 1.4
)

// vacuumRateMinLive: a run over less live data than this measures the fixed
// costs, not the rate, and is not recorded as this host's.  A variable so a
// test can record one from a small database.
var vacuumRateMinLive int64 = 256 << 20

// VacuumPlan is what a compaction would do and need, worked out before it
// starts: the numbers the admin UI shows next to the button and `unmask
// db-vacuum` prints before it runs.
type VacuumPlan struct {
	// FileBytes / LiveBytes: the file, and the data in use (pages not on the
	// free list).  Reclaim is what the file gives back: the difference.
	FileBytes int64
	LiveBytes int64
	Reclaim   int64
	WALBytes  int64
	// DiskNeed: the free space the run needs next to the database; DiskFree
	// what there is (-1 when it cannot be read).
	DiskNeed int64
	DiskFree int64
	// EstLow / EstHigh: how long it is expected to take.  EstFrom says where
	// the rate came from: "measured" (this host's last compaction), "index"
	// (this host's last index build) or "default" (the built-in range).
	EstLow  time.Duration
	EstHigh time.Duration
	EstFrom string
	// EventsPerHour: the recent rate of events -- what the daemon holds for
	// every hour the run takes.  HeldEvents is that over EstHigh, HeldBytes
	// its memory, and HeldLimit how many events the daemon keeps before it
	// drops the oldest.  CountersBytes bounds the access-log counters the
	// daemon keeps besides.
	EventsPerHour int64
	HeldEvents    int64
	HeldBytes     int64
	HeldLimit     int64
	CountersBytes int64
}

// Worth reports whether a compaction gives back enough to be worth holding the
// writes for: at least a fifth of the file, and 64 MB.
func (p VacuumPlan) Worth() bool {
	return p.Reclaim >= 64<<20 && p.Reclaim*5 >= p.FileBytes
}

// DiskShort reports whether the free space next to the database is known to be
// short of what the run needs.
func (p VacuumPlan) DiskShort() bool { return p.DiskFree >= 0 && p.DiskFree < p.DiskNeed }

// HeldOver reports whether the daemon is expected to hold more events than it
// keeps: the oldest would be dropped before the run ends.
func (p VacuumPlan) HeldOver() bool { return p.HeldEvents > p.HeldLimit }

// PlanVacuum works out what a compaction of this database would take.  Reads
// only: the page accounting, the free space, the recent event rate and the
// rates this host recorded.
func (d *DB) PlanVacuum(ctx context.Context) (VacuumPlan, error) {
	var p VacuumPlan
	if d == nil || d.Driver != DriverSQLite {
		return p, ErrVacuumSQLiteOnly
	}
	sp, err := d.Space(ctx)
	if err != nil {
		return p, err
	}
	p.FileBytes, p.LiveBytes = sp.FileBytes, sp.LiveBytes
	if p.Reclaim = p.FileBytes - p.LiveBytes; p.Reclaim < 0 {
		p.Reclaim = 0
	}
	p.WALBytes = d.WALSize()
	p.DiskNeed = VacuumDiskNeed(p.LiveBytes)
	p.DiskFree = -1
	if d.SQLitePath != "" {
		if f, err := dirFree(filepath.Dir(d.SQLitePath)); err == nil {
			p.DiskFree = f
		}
	}

	gbLive := float64(p.LiveBytes) / (1 << 30)
	var low, high float64 // seconds per live GB
	var rate VacuumRateRecord
	if has, _ := hasTable(d, "unmask_maint_state"); has && d.Gorm != nil {
		if got, err := d.LoadMaintState(ctx, MaintVacuumRate, &rate); err == nil && got && rate.SecondsPerGB > 0 {
			low, high, p.EstFrom = rate.SecondsPerGB*vacuumMeasuredLow, rate.SecondsPerGB*vacuumMeasuredHigh, "measured"
		}
	}
	// The index rate and the built-in range are the disk's: VACUUM reads
	// every page of the file, the ones no query has touched in weeks too, and
	// writes the data out twice over -- a database that fits in memory is
	// not one it finds cached.  A host's index rate measured from the cache
	// is held to the disk's for the high end, which the held-events check
	// is made against.
	diskFast := float64(indexBuildDiskFast.Microseconds())
	if p.EstFrom == "" {
		if us := hostIndexRate(d); us > 0 {
			low, high, p.EstFrom = us*vacuumPerIndexRateLow, max(us, diskFast)*vacuumPerIndexRateHigh, "index"
		}
	}
	if p.EstFrom == "" {
		low = diskFast * vacuumPerIndexRateLow
		high = float64(indexBuildDiskSlow.Microseconds()) * vacuumPerIndexRateHigh
		p.EstFrom = "default"
	}
	p.EstLow = time.Duration(low * gbLive * float64(time.Second))
	p.EstHigh = time.Duration(high * gbLive * float64(time.Second))

	p.EventsPerHour = d.recentEventsPerHour(ctx)
	p.HeldEvents = int64(math.Ceil(float64(p.EventsPerHour) * p.EstHigh.Hours()))
	p.HeldBytes = p.HeldEvents * HeldEventBytes
	p.HeldLimit = int64(HeldEventsLimit())
	p.CountersBytes = heldCountersBytes
	return p, nil
}

// recentEventsPerHour is the event rate the daemon will hold during a run: the
// busier of the last hour and the last day's average.  Both ride the date
// index; the day's count is given up (the hour stands) past a short deadline
// on a database too large to count it quickly.
func (d *DB) recentEventsPerHour(ctx context.Context) int64 {
	now := time.Now().UTC()
	count := func(since time.Duration, within time.Duration) (int64, bool) {
		c, cancel := context.WithTimeout(ctx, within)
		defer cancel()
		var n int64
		err := d.QueryRowContext(c, `SELECT COUNT(*) FROM unmask_event`+d.EventDateIndexHint("x")+
			` WHERE date_created >= ?`, now.Add(-since).Format("2006-01-02 15:04:05.000")).Scan(&n)
		return n, err == nil
	}
	hour, _ := count(time.Hour, 3*time.Second)
	if day, ok := count(24*time.Hour, 3*time.Second); ok && day/24 > hour {
		return day / 24
	}
	return hour
}

// VacuumProgress estimates how far a running compaction has got, from the
// outside: VACUUM is one statement and reports nothing while it runs.  It
// first writes its copy into a temporary file in the database's directory --
// a file no listing shows, whose size is read off the directory's free space
// -- and then copies it back through the write-ahead log, whose growth is
// plain.  frac runs 0..0.99 over the two halves; phase is "copy" or "write".
func VacuumProgress(rec VacuumRecord, diskFreeNow, walNow int64) (frac float64, phase string) {
	live := rec.LiveBefore
	if live <= 0 {
		return 0, "copy"
	}
	walGrown := walNow - rec.WALAtStart
	if walGrown < 0 {
		walGrown = 0
	}
	clamp := func(f float64) float64 {
		switch {
		case f < 0:
			return 0
		case f > 0.99:
			return 0.99
		}
		return f
	}
	// The copy back has begun once the log holds a twentieth of the data:
	// before that, its growth is the daemon's own writes that got in.
	if walGrown*20 >= live {
		return clamp(0.5 + 0.5*float64(walGrown)/float64(live)), "write"
	}
	copied := rec.DiskFreeAtStart - diskFreeNow - walGrown
	return clamp(0.5 * float64(copied) / float64(live)), "copy"
}

// VacuumOptions tunes RunVacuum.
type VacuumOptions struct {
	// Host / By: for the record (the daemon's host id; an administrator's
	// username or VacuumByCLI).
	Host string
	By   string
	// Logf receives the plan and the progress lines.  nil discards them.
	Logf func(format string, args ...any)
	// SkipSpaceCheck runs even when the free space next to the database looks
	// short of VacuumDiskNeed.
	SkipSpaceCheck bool
	// WaitHeld returns once the daemon, if one is running, has stopped
	// writing (see the hand-over above), or with why it has not.  It is
	// called with the run on record and before VACUUM takes the write lock.
	// nil waits for nothing.
	WaitHeld func(ctx context.Context) error
}

// VacuumResult is what a run did.
type VacuumResult struct {
	FileBefore int64
	LiveBefore int64
	FileAfter  int64
	Elapsed    time.Duration
}

// vacuumCacheKiB is the page cache the run's connection uses: measured at
// about 180 MB of process memory for the whole run with it, where 32 MB took
// 240 and 8 MB 120 -- without making the run faster.
const vacuumCacheKiB = 16 << 10

// vacuumLockWait is how long VACUUM waits for the write lock when it starts:
// long enough for a write the daemon began before it stopped writing -- a
// prune chunk, a rollup -- to finish.
const vacuumLockWait = 60 * time.Second

// checkpointAfterVacuumWithin bounds the wait for the copied-back database to
// be checkpointed out of the write-ahead log before the run ends.
const checkpointAfterVacuumWithin = 10 * time.Minute

// RunVacuum compacts the database conn is open on.  conn must be a
// maintenance connection (OpenMaintenance): one connection, and SQLite's
// temporary files -- VACUUM's copy of the whole database -- on disk next to it
// rather than in memory.
//
// It holds the run lock (LockVacuumRun) from before its record is written
// until the record says how the run ended.  ctx cancels it: SQLite rolls the
// VACUUM back and the database is as it was.
func RunVacuum(ctx context.Context, conn *DB, opt VacuumOptions) (VacuumResult, error) {
	var res VacuumResult
	logf := func(format string, args ...any) {
		if opt.Logf != nil {
			opt.Logf(format, args...)
		}
	}
	if conn == nil || conn.Driver != DriverSQLite || conn.SQLitePath == "" {
		return res, ErrVacuumSQLiteOnly
	}
	if has, err := hasTable(conn, "unmask_maint_state"); err != nil || !has {
		return res, errors.New("the database has no schema yet; run `unmask migrate` first")
	}
	lock, err := conn.LockVacuumRun(ctx)
	if err != nil {
		if errors.Is(err, ErrVacuumRunning) {
			if prev, ok, lerr := conn.LoadVacuum(ctx); lerr == nil && ok && prev.State == VacuumRunning {
				return res, fmt.Errorf("%w (started %s by %s on %s, pid %d)", ErrVacuumRunning,
					time.Unix(prev.StartedAt, 0).UTC().Format("2006-01-02 15:04 UTC"), prev.By, prev.Host, prev.PID)
			}
		}
		return res, err
	}
	defer lock.Release()
	// A schema update holds the same write lock for as long as it builds;
	// the two would only fail each other.  Its run looks for this one too.
	if held, _ := conn.SchemaRunLockHeld(ctx); held {
		return res, ErrSchemaUpdateRunning
	}

	plan, err := conn.PlanVacuum(ctx)
	if err != nil {
		return res, err
	}
	res.FileBefore, res.LiveBefore = plan.FileBytes, plan.LiveBytes
	rec := VacuumRecord{
		State: VacuumRunning, Host: opt.Host, PID: os.Getpid(), By: opt.By,
		StartedAt: time.Now().Unix(), EstLowSec: int(plan.EstLow.Seconds()), EstHighSec: int(plan.EstHigh.Seconds()),
		FileBefore: plan.FileBytes, LiveBefore: plan.LiveBytes, DiskFreeAtStart: plan.DiskFree, WALAtStart: plan.WALBytes,
	}
	if err := conn.SaveMaintState(ctx, MaintVacuum, rec); err != nil {
		return res, fmt.Errorf("record the run: %w", err)
	}
	logf("file %s, %s in use: %s to give back; estimated %s", humanBytes(plan.FileBytes), humanBytes(plan.LiveBytes),
		humanBytes(plan.Reclaim), EstimateRange(plan.EstLow, plan.EstHigh))

	t0 := time.Now()
	runErr := func() error {
		// Checked once the run is on record, so that a refusal is on
		// record too: a run started from the admin UI has nobody reading
		// its terminal.
		if !opt.SkipSpaceCheck && plan.DiskShort() {
			return fmt.Errorf("compaction needs about %s free in %s (the copy, and the same again while it is written back) and %s is available; free some space, or run `unmask db-vacuum -skip-space-check` to go ahead anyway",
				humanBytes(plan.DiskNeed), filepath.Dir(conn.SQLitePath), humanBytes(plan.DiskFree))
		}
		if opt.WaitHeld != nil {
			if err := opt.WaitHeld(ctx); err != nil {
				return err
			}
		}
		for _, p := range []string{
			fmt.Sprintf("PRAGMA cache_size=-%d", vacuumCacheKiB),
			fmt.Sprintf("PRAGMA busy_timeout=%d", vacuumLockWait.Milliseconds()),
		} {
			if _, err := conn.ExecContext(ctx, p); err != nil {
				return err
			}
		}
		defer func() { _, _ = conn.ExecContext(context.Background(), "PRAGMA busy_timeout=5000") }()
		logf("compacting (the daemon keeps serving; its writes wait until this ends)")
		if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
			return err
		}
		logf("compacted in %s; writing it out of the write-ahead log", time.Since(t0).Round(time.Second))
		return checkpointAfterVacuum(conn, logf)
	}()
	res.Elapsed = time.Since(t0)
	if st, err := os.Stat(conn.SQLitePath); err == nil {
		res.FileAfter = st.Size()
	}

	wctx, wcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer wcancel()
	rec.EndedAt, rec.Seconds = time.Now().Unix(), res.Elapsed.Seconds()
	switch {
	case runErr == nil:
		rec.State, rec.FileAfter = VacuumDone, res.FileAfter
		if plan.LiveBytes >= vacuumRateMinLive {
			r := VacuumRateRecord{
				SecondsPerGB: res.Elapsed.Seconds() / (float64(plan.LiveBytes) / (1 << 30)),
				LiveBytes:    plan.LiveBytes, MeasuredAt: time.Now().Unix(),
			}
			if err := conn.SaveMaintState(wctx, MaintVacuumRate, r); err != nil {
				logf("could not record this host's compaction rate: %v", err)
			}
		}
	case ctx.Err() != nil:
		rec.State, rec.Err = VacuumCancelled, "cancelled"
	default:
		rec.State, rec.Err = VacuumFailed, runErr.Error()
	}
	// The record outlives the run's context: a cancelled run still has to
	// say it was cancelled.
	if err := conn.SaveMaintState(wctx, MaintVacuum, rec); err != nil {
		logf("could not record how the run ended: %v", err)
	}
	if runErr != nil && ctx.Err() != nil {
		return res, fmt.Errorf("cancelled: %w", ctx.Err())
	}
	return res, runErr
}

// checkpointAfterVacuum moves the copied-back database out of the write-ahead
// log before the run lets the daemon write again.
//
// VACUUM's last step writes every page into the log.  The checkpoint that
// follows its commit copies them into the file, but it stops at the first
// frame a reader still holding the old snapshot may need -- and whatever it
// leaves is copied by the next checkpoint, which after the run would be the
// daemon's own, inside the first write it makes.  Measured: that write waited
// 5.7 s over a 0.85 GB log; a large database's is minutes.  So the run copies
// until the log is all in the file (the daemon's readers finish in moments),
// then truncates it if nobody is on it.
func checkpointAfterVacuum(conn *DB, logf func(string, ...any)) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkpointAfterVacuumWithin)
	defer cancel()
	for {
		cp, err := conn.CheckpointWAL(ctx, "PASSIVE", 0)
		if err != nil {
			return fmt.Errorf("write-ahead log checkpoint: %w", err)
		}
		if !cp.Busy && cp.Checkpointed >= cp.LogFrames {
			break
		}
		select {
		case <-ctx.Done():
			// Compacted and committed all the same: what is left is the
			// daemon's to copy.
			logf("the write-ahead log is not all checkpointed yet (%d of %d pages); the daemon finishes it", cp.Checkpointed, cp.LogFrames)
			return nil
		case <-time.After(200 * time.Millisecond):
		}
	}
	for i := 0; i < 10; i++ {
		tc, err := conn.CheckpointWAL(ctx, "TRUNCATE", time.Second)
		if err == nil && !tc.Busy {
			return nil
		}
	}
	logf("the write-ahead log stays at its size until the daemon trims it (a reader was on it)")
	return nil
}

// humanBytes: "1.4 GB", "512 MB", "12 KB".
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
