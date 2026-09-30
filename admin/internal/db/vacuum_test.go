package db

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// fragmentedDB is a migrated database holding n events, of which every other
// one has been deleted: a file whose free pages are scattered through it, the
// state the retention prune leaves.
func fragmentedDB(t *testing.T, n int) *DB {
	t.Helper()
	d := migratedDB(t)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO unmask_event (site, host, ip_address, user_agent, ja4, phase, payload_json, date_created)
		VALUES ('s', 'h', ?, ?, ?, 'serve', ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	// One a second up to now: the recent rate PlanVacuum reads is theirs.
	base := time.Now().UTC().Add(-time.Duration(n) * time.Second)
	for i := 0; i < n; i++ {
		ip := []byte{10, byte(i >> 16), byte(i >> 8), byte(i)}
		if _, err := stmt.Exec(ip, fmt.Sprintf("Mozilla/5.0 test agent %d with some length to it", i%97),
			fmt.Sprintf("t13d%04d_%08x", i%500, i), fmt.Sprintf(`{"bt":"tok.%08x","orig_path":"/p/%d?a=1&b=2"}`, i, i),
			base.Add(time.Duration(i)*time.Second).Format("2006-01-02 15:04:05.000")); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM unmask_event WHERE id % 2 = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	return d
}

// maintOf opens the maintenance connection a run uses, on d's file.
func maintOf(t *testing.T, d *DB) *DB {
	t.Helper()
	m, err := OpenMaintenance(settings.DB{Driver: "sqlite", SQLitePath: d.SQLitePath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func countEvents(t *testing.T, d *DB) (n int64, sum int64) {
	t.Helper()
	if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(id), 0) FROM unmask_event`).Scan(&n, &sum); err != nil {
		t.Fatal(err)
	}
	return n, sum
}

// A run gives the freed pages back and keeps every row, records how it went,
// and leaves nothing behind: the write-ahead log checkpointed, the lock free.
func TestRunVacuumCompacts(t *testing.T) {
	d := fragmentedDB(t, 20000)
	before, sumBefore := countEvents(t, d)
	plan, err := d.PlanVacuum(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reclaim <= 0 || plan.LiveBytes <= 0 || plan.FileBytes <= plan.LiveBytes {
		t.Fatalf("plan = %+v: a half-deleted file has pages to give back", plan)
	}
	if plan.DiskNeed != VacuumDiskNeed(plan.LiveBytes) || plan.DiskNeed < 2*plan.LiveBytes {
		t.Errorf("DiskNeed = %d for %d live: the copy and the write-back both need room", plan.DiskNeed, plan.LiveBytes)
	}

	prevMin := vacuumRateMinLive
	vacuumRateMinLive = 0
	defer func() { vacuumRateMinLive = prevMin }()

	m := maintOf(t, d)
	waited := false
	res, err := RunVacuum(context.Background(), m, VacuumOptions{
		Host: "h1", By: "tester",
		WaitHeld: func(context.Context) error {
			// The hand-over comes with the run on record and the lock held.
			rec, ok, err := d.LoadVacuum(context.Background())
			if err != nil || !ok || rec.State != VacuumRunning || rec.PID != os.Getpid() {
				t.Errorf("at the hand-over the record reads %+v (ok=%v err=%v), want this run as running", rec, ok, err)
			}
			if held, known := d.VacuumRunLockHeld(); !known || !held {
				t.Error("at the hand-over the run lock is not held")
			}
			waited = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !waited {
		t.Error("the run did not wait for the daemon's hand-over")
	}
	if res.FileAfter >= res.FileBefore {
		t.Errorf("file %d -> %d: nothing given back", res.FileBefore, res.FileAfter)
	}
	after, sumAfter := countEvents(t, d)
	if after != before || sumAfter != sumBefore {
		t.Errorf("rows %d (id sum %d) -> %d (%d): a compaction keeps every row", before, sumBefore, after, sumAfter)
	}
	var qc string
	if err := d.QueryRow(`PRAGMA quick_check`).Scan(&qc); err != nil || qc != "ok" {
		t.Errorf("quick_check = %q (%v)", qc, err)
	}
	rec, ok, err := d.LoadVacuum(context.Background())
	if err != nil || !ok {
		t.Fatalf("record: ok=%v err=%v", ok, err)
	}
	if rec.State != VacuumDone || rec.By != "tester" || rec.Host != "h1" || rec.FileBefore != res.FileBefore || rec.FileAfter != res.FileAfter || rec.EndedAt == 0 {
		t.Errorf("record = %+v, want done with the sizes", rec)
	}
	if d.VacuumAlive(rec, time.Now()) {
		t.Error("a finished run reads as alive")
	}
	if held, _ := d.VacuumRunLockHeld(); held {
		t.Error("the run lock is still held after the run")
	}
	var rate VacuumRateRecord
	if ok, err := d.LoadMaintState(context.Background(), MaintVacuumRate, &rate); err != nil || !ok || rate.SecondsPerGB <= 0 {
		t.Errorf("rate record: %+v ok=%v err=%v", rate, ok, err)
	}
	// The next plan is estimated from this host's own compaction.
	if p2, err := d.PlanVacuum(context.Background()); err != nil || p2.EstFrom != "measured" {
		t.Errorf("next plan EstFrom = %q (%v), want measured", p2.EstFrom, err)
	}
	// The copied-back database is out of the log: the daemon's first write
	// after the run must not have to copy it.
	if w := d.WALSize(); w > 64<<20 {
		t.Errorf("write-ahead log %d bytes after the run", w)
	}
}

// A run that is stopped before VACUUM changes nothing and says it was
// cancelled; one that is refused for space says why, on record.
func TestRunVacuumCancelAndRefusal(t *testing.T) {
	d := fragmentedDB(t, 4000)
	before, _ := countEvents(t, d)
	st0, _ := os.Stat(d.SQLitePath)
	m := maintOf(t, d)

	ctx, cancel := context.WithCancel(context.Background())
	_, err := RunVacuum(ctx, m, VacuumOptions{By: "tester", WaitHeld: func(c context.Context) error {
		cancel()
		return c.Err()
	}})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err = %v, want cancelled", err)
	}
	rec, _, _ := d.LoadVacuum(context.Background())
	if rec.State != VacuumCancelled {
		t.Errorf("record state %q, want cancelled", rec.State)
	}
	st1, _ := os.Stat(d.SQLitePath)
	if after, _ := countEvents(t, d); after != before || st1.Size() != st0.Size() {
		t.Errorf("a cancelled run changed the database: rows %d -> %d, file %d -> %d", before, after, st0.Size(), st1.Size())
	}

	prev := dirFree
	dirFree = func(string) (int64, error) { return 1 << 10, nil }
	defer func() { dirFree = prev }()
	_, err = RunVacuum(context.Background(), m, VacuumOptions{By: "tester"})
	if err == nil || !strings.Contains(err.Error(), "free") {
		t.Fatalf("err = %v, want a refusal for space", err)
	}
	rec, _, _ = d.LoadVacuum(context.Background())
	if rec.State != VacuumFailed || !strings.Contains(rec.Err, "free") {
		t.Errorf("record = %+v, want the refusal on record", rec)
	}
	if held, _ := d.VacuumRunLockHeld(); held {
		t.Error("the lock stays held after a refused run")
	}
}

// A compaction and a schema update hold the same write lock for as long as
// they run: whichever comes second is turned away.
func TestVacuumAndSchemaUpdateExcludeEachOther(t *testing.T) {
	d := migratedDB(t)
	asBeforeTheIndex(t, d, 50)

	lock, err := d.LockSchemaRun(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := maintOf(t, d)
	if _, err := RunVacuum(context.Background(), m, VacuumOptions{}); !errors.Is(err, ErrSchemaUpdateRunning) {
		t.Errorf("vacuum during a schema update: err = %v, want ErrSchemaUpdateRunning", err)
	}
	lock.Release()

	vlock, err := d.LockVacuumRun(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer vlock.Release()
	if _, err := ApplySchemaUpdate(context.Background(), d, SchemaUpdateOptions{By: "tester"}); !errors.Is(err, ErrVacuumRunning) {
		t.Errorf("schema update during a vacuum: err = %v, want ErrVacuumRunning", err)
	}
	if _, err := d.LockVacuumRun(context.Background()); !errors.Is(err, ErrVacuumRunning) {
		t.Errorf("a second vacuum lock: err = %v, want ErrVacuumRunning", err)
	}
}

// The estimate follows the best rate this host has: its own compaction, then
// its own index build, then the built-in range -- and the events the daemon
// holds follow the estimate.
func TestPlanVacuumEstimate(t *testing.T) {
	d := fragmentedDB(t, 2000)
	ctx := context.Background()
	p, err := d.PlanVacuum(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.EstFrom != "default" {
		t.Errorf("EstFrom = %q with no rate recorded", p.EstFrom)
	}
	// An index rate measured from the cache is held to the disk's at the
	// high end: VACUUM reads the whole file, cached or not.
	if err := d.SaveMaintState(ctx, MaintSchemaRate, SchemaRateRecord{MicrosPerRow: 5, Rows: 1e6, MeasuredAt: 1}); err != nil {
		t.Fatal(err)
	}
	p, _ = d.PlanVacuum(ctx)
	if gb := float64(p.LiveBytes) / (1 << 30); p.EstFrom != "index" || !near(p.EstHigh.Seconds(), 60*vacuumPerIndexRateHigh*gb) {
		t.Errorf("from a cached index rate: %+v", p)
	}
	if err := d.SaveMaintState(ctx, MaintSchemaRate, SchemaRateRecord{MicrosPerRow: 100, Rows: 1e6, MeasuredAt: 1}); err != nil {
		t.Fatal(err)
	}
	p, _ = d.PlanVacuum(ctx)
	gb := float64(p.LiveBytes) / (1 << 30)
	if p.EstFrom != "index" || !near(p.EstLow.Seconds(), 100*vacuumPerIndexRateLow*gb) || !near(p.EstHigh.Seconds(), 100*vacuumPerIndexRateHigh*gb) {
		t.Errorf("from an index rate: %+v", p)
	}
	if err := d.SaveMaintState(ctx, MaintVacuumRate, VacuumRateRecord{SecondsPerGB: 60, LiveBytes: 1 << 30, MeasuredAt: 1}); err != nil {
		t.Fatal(err)
	}
	p, _ = d.PlanVacuum(ctx)
	if p.EstFrom != "measured" || !near(p.EstLow.Seconds(), 60*0.8*gb) || !near(p.EstHigh.Seconds(), 60*1.4*gb) {
		t.Errorf("from a measured rate: %+v", p)
	}
	// Events: 2,000 rows over the last half hour, half of them deleted.
	if p.EventsPerHour <= 0 {
		t.Errorf("EventsPerHour = %d", p.EventsPerHour)
	}
	if want := int64(math.Ceil(float64(p.EventsPerHour) * p.EstHigh.Hours())); p.HeldEvents != want {
		t.Errorf("HeldEvents = %d, want %d", p.HeldEvents, want)
	}
	if p.HeldLimit < heldEventsFloor || p.HeldBytes != p.HeldEvents*HeldEventBytes || p.CountersBytes <= 0 {
		t.Errorf("held: %+v", p)
	}
}

func near(a, b float64) bool { return a >= b*0.99-0.01 && a <= b*1.01+0.01 }

func TestVacuumPlanVerdicts(t *testing.T) {
	cases := []struct {
		p                    VacuumPlan
		worth, short, heldOK bool
	}{
		{VacuumPlan{FileBytes: 10 << 30, LiveBytes: 4 << 30, Reclaim: 6 << 30, DiskNeed: 9 << 30, DiskFree: 100 << 30, HeldEvents: 10, HeldLimit: 50000}, true, false, true},
		{VacuumPlan{FileBytes: 10 << 30, LiveBytes: 9 << 30, Reclaim: 1 << 30, DiskNeed: 20 << 30, DiskFree: 5 << 30, HeldEvents: 60000, HeldLimit: 50000}, false, true, false},
		{VacuumPlan{FileBytes: 100 << 20, LiveBytes: 50 << 20, Reclaim: 50 << 20, DiskNeed: 110 << 20, DiskFree: -1}, false, false, true},
	}
	for i, c := range cases {
		if c.p.Worth() != c.worth || c.p.DiskShort() != c.short || c.p.HeldOver() == c.heldOK {
			t.Errorf("case %d: worth=%v short=%v heldOver=%v", i, c.p.Worth(), c.p.DiskShort(), c.p.HeldOver())
		}
	}
	if HeldEventsLimit() < heldEventsFloor {
		t.Errorf("HeldEventsLimit = %d", HeldEventsLimit())
	}
}

// Progress is read from the outside: the copy through the directory's free
// space, the write-back through the log's growth.
func TestVacuumProgress(t *testing.T) {
	rec := VacuumRecord{LiveBefore: 1000, DiskFreeAtStart: 10000, WALAtStart: 40}
	cases := []struct {
		free, wal int64
		frac      float64
		phase     string
	}{
		{10000, 40, 0, "copy"},
		{9500, 40, 0.25, "copy"},
		{9000, 60, 0.49, "copy"}, // 20 bytes of the daemon's own writes, not the write-back
		{8900, 540, 0.75, "write"},
		{8000, 2000, 0.99, "write"},
		{12000, 0, 0, "copy"},
	}
	for _, c := range cases {
		f, ph := VacuumProgress(rec, c.free, c.wal)
		if ph != c.phase || f < c.frac-0.011 || f > c.frac+0.011 {
			t.Errorf("free %d wal %d: %.3f %s, want %.2f %s", c.free, c.wal, f, ph, c.frac, c.phase)
		}
	}
}

// The hand-over names one run: a file left by an earlier run's daemon does not
// release a later one.
func TestVacuumHeldHandover(t *testing.T) {
	d := migratedDB(t)
	if d.VacuumHeldFor(123) {
		t.Fatal("held before anything was written")
	}
	if err := d.WriteVacuumHeld(123); err != nil {
		t.Fatal(err)
	}
	if !d.VacuumHeldFor(123) || d.VacuumHeldFor(124) {
		t.Error("the hand-over does not name its run")
	}
}
