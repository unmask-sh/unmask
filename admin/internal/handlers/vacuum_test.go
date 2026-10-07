package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// vacuumHandler is a handler over a migrated database holding n events, every
// other one of them deleted: a file with free pages scattered through it.
func vacuumHandler(t *testing.T, n int) *Handler {
	t.Helper()
	cfg := settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "v.sqlite")}
	conn, err := db.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := tx.Exec(`INSERT INTO unmask_event (site, host, ip_address, user_agent, ja4, phase, payload_json, date_created)
			VALUES ('s', 'h', ?, 'Mozilla/5.0 (test)', ?, 'serve', ?, CURRENT_TIMESTAMP)`,
			[]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}, fmt.Sprintf("t13d%04d_%06x", i%97, i),
			fmt.Sprintf(`{"bt":"tok.%08x","orig_path":"/page/%d"}`, i, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`DELETE FROM unmask_event WHERE id % 2 = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: conn, HostID: "test-host", UserRepo: user.New(conn)}
	h.SetSettings(settings.Settings{
		DB:     cfg,
		Server: settings.Server{BasePath: "/unmask"},
		Secret: settings.Secret{BVSecret: "test-secret", CaptchaSecretBase: "test-base"},
	})
	return h
}

// TestVacuumHelper is the compaction run the tests start in place of `unmask
// db-vacuum`: RunVacuum on a maintenance connection, waiting for the daemon's
// hand-over as the command does.  UNMASK_TEST_VACUUM_HOLD keeps it at the
// hand-over that long first -- with the run lock held and its record written,
// which is what a compaction of a large file looks like from outside.
func TestVacuumHelper(t *testing.T) {
	path := os.Getenv("UNMASK_TEST_VACUUM_DB")
	if path == "" {
		t.Skip("helper process for the compaction tests")
	}
	hold, _ := time.ParseDuration(os.Getenv("UNMASK_TEST_VACUUM_HOLD"))
	conn, err := db.OpenMaintenance(settings.DB{Driver: "sqlite", SQLitePath: path})
	if err != nil {
		fmt.Println("helper: open:", err)
		os.Exit(3)
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_, err = db.RunVacuum(ctx, conn, db.VacuumOptions{
		Host: os.Getenv("UNMASK_TEST_VACUUM_HOST"), By: os.Getenv("UNMASK_TEST_VACUUM_BY"),
		Logf: func(f string, a ...any) { fmt.Printf("db-vacuum: "+f+"\n", a...) },
		WaitHeld: func(ctx context.Context) error {
			deadline := time.Now().Add(10 * time.Second)
			for !conn.VacuumHeldFor(os.Getpid()) {
				if time.Now().After(deadline) {
					return fmt.Errorf("the daemon did not stop writing")
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(20 * time.Millisecond):
				}
			}
			select {
			case <-time.After(hold):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	if err != nil {
		fmt.Println("db-vacuum:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// vacuumHelperArgs start this test binary as TestVacuumHelper.
var vacuumHelperArgs = []string{"-test.run=^TestVacuumHelper$"}

func vacuumHelperEnv(h *Handler, hold time.Duration, by string) []string {
	return append(os.Environ(),
		"UNMASK_TEST_VACUUM_DB="+h.cfg().DB.SQLitePath,
		"UNMASK_TEST_VACUUM_HOLD="+hold.String(),
		"UNMASK_TEST_VACUUM_HOST="+h.HostID,
		"UNMASK_TEST_VACUUM_BY="+by,
	)
}

// vacuumHelperCommand makes h start TestVacuumHelper where it would start
// `unmask db-vacuum`.
func vacuumHelperCommand(h *Handler, hold time.Duration) {
	h.VacuumCommand = func(by string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], vacuumHelperArgs...)
		cmd.Env = vacuumHelperEnv(h, hold, by)
		out := &logLines{prefix: "db vacuum: "}
		cmd.Stdout, cmd.Stderr = out, out
		return cmd, nil
	}
}

func fileSizeOf(t *testing.T, p string) int64 {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

// The button: the run is a process of its own; from the moment it is started
// the daemon's writers stand back and the events that arrive are kept; a
// second run and a schema update are turned away; afterwards the file is
// smaller, the kept events are written, and the notice says how it went.
func TestVacuumRunFromTheUI(t *testing.T) {
	h := vacuumHandler(t, 3000)
	vacuumHelperCommand(h, 1500*time.Millisecond)
	fl := events.NewFlusher(h.DB, 10, 50)
	defer fl.Stop()
	loads := func() int {
		var n int
		if err := h.DB.QueryRow(`SELECT COUNT(*) FROM unmask_event WHERE phase = 'load'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := fileSizeOf(t, h.DB.SQLitePath)

	code, body := postJSON(t, h.AdminVacuumRun, "/unmask/admin/api/vacuum/run", user.RoleSuperadmin)
	if code != http.StatusOK {
		t.Fatalf("run: %d %v", code, body)
	}
	if !h.DB.WritesHeld() || !h.DB.WritesHeldForVacuum() {
		t.Fatal("writes must be held from the moment the run is started, before it can take the lock")
	}
	if code, _ := postJSON(t, h.AdminVacuumRun, "/unmask/admin/api/vacuum/run", user.RoleSuperadmin); code != http.StatusConflict {
		t.Errorf("second run: %d, want 409", code)
	}
	if err := h.schemaReserve(); err != db.ErrVacuumRunning {
		t.Errorf("a schema update during a compaction: %v, want ErrVacuumRunning", err)
	}

	waitFor(t, "the run's record", 20*time.Second, func() bool {
		h.VacuumRefresh(context.Background())
		rec, ok, err := h.DB.LoadVacuum(context.Background())
		return err == nil && ok && rec.State == db.VacuumRunning && h.DB.VacuumAlive(rec, time.Now())
	})
	// The last try refreshed before it read the record (see waitForRecord).
	h.VacuumRefresh(context.Background())
	v := h.vacuumView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "running" || !v.CanCancel || v.StartedAt == 0 || v.By == "" {
		t.Fatalf("view while running = %+v", v)
	}
	limit := groupDigits(int64(db.HeldEventsLimit()))
	if v.StepText == "" || v.PillText == "" || v.Steps < 3 || len(v.Bars) != v.Steps ||
		!strings.Contains(v.HeldText, limit) || v.CancelNote != i18n.T(i18n.LangEN, "vacuum.cancel_note") || v.StopHint != "" {
		t.Errorf("view while running: step %q / %q of %d (%d bars), held %q, note %q, hint %q",
			v.StepText, v.PillText, v.Steps, len(v.Bars), v.HeldText, v.CancelNote, v.StopHint)
	}
	if other := h.vacuumView(user.RoleAdmin, i18n.LangEN); other == nil || other.State != "running" || other.CanCancel ||
		other.StopHint != i18n.T(i18n.LangEN, "vacuum.stop_hint_role") {
		t.Errorf("admin view while running = %+v", other)
	}
	for i := 0; i < 25; i++ {
		fl.Submit(&events.Event{Site: "s", IPPacked: []byte{10, 0, 0, 9}, Phase: "load"})
	}
	time.Sleep(300 * time.Millisecond)
	if n := loads(); n != 0 {
		t.Errorf("%d events were written during the run; they are to be kept", n)
	}

	waitFor(t, "the run to end", 30*time.Second, func() bool {
		h.VacuumRefresh(context.Background())
		return !h.VacuumGoing() && !h.DB.WritesHeld()
	})
	waitFor(t, "the kept events to be written", 5*time.Second, func() bool { return loads() == 25 })
	rec, ok, err := h.DB.LoadVacuum(context.Background())
	if err != nil || !ok || rec.State != db.VacuumDone || rec.By == "" {
		t.Fatalf("record = (%+v, %v, %v)", rec, ok, err)
	}
	if after := fileSizeOf(t, h.DB.SQLitePath); after >= before {
		t.Errorf("file %d -> %d: nothing given back", before, after)
	}
	v = h.vacuumView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "done" || v.FileBefore == "" || v.FileAfter == "" || v.Took == "" {
		t.Errorf("view after = %+v", v)
	}
	if _, err := os.Stat(h.DB.VacuumHeldPath()); err != nil {
		t.Errorf("the hand-over file was not written: %v", err)
	}
}

// Cancelled from the card: the run is stopped, SQLite rolls the VACUUM back,
// the record says so and the writes are released.
func TestVacuumCancelFromTheUI(t *testing.T) {
	h := vacuumHandler(t, 2000)
	vacuumHelperCommand(h, time.Minute)
	before := fileSizeOf(t, h.DB.SQLitePath)
	if code, body := postJSON(t, h.AdminVacuumRun, "/unmask/admin/api/vacuum/run", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("run: %d %v", code, body)
	}
	waitFor(t, "the run's record", 20*time.Second, func() bool {
		h.VacuumRefresh(context.Background())
		rec, ok, _ := h.DB.LoadVacuum(context.Background())
		return ok && rec.State == db.VacuumRunning && h.DB.VacuumAlive(rec, time.Now())
	})
	h.VacuumRefresh(context.Background()) // as above: the view must hold the record too
	// The card has the run where its button was, with the cancel button for
	// the superadmin whose daemon started it.
	body := renderTab(t, h, "retention", user.RoleSuperadmin, "en")
	for _, w := range []string{`id="vacuum-progress"`, `id="vacuum-cancel"`, `id="vacuum-stop-dialog"`, i18n.T(i18n.LangEN, "vacuum.running_sub")} {
		if !strings.Contains(body, w) {
			t.Errorf("the card of a running compaction lacks %q", w)
		}
	}
	if strings.Contains(body, `id="vacuum-run"`) || strings.Contains(body, `id="vacuum-dialog"`) {
		t.Error("the card offers to start a compaction while one runs")
	}
	if body := renderTab(t, h, "retention", user.RoleAdmin, "en"); !strings.Contains(body, `id="vacuum-progress"`) ||
		strings.Contains(body, `id="vacuum-cancel"`) || strings.Contains(body, `id="vacuum-stop-dialog"`) {
		t.Error("an admin's card: the run's progress, and no cancel button")
	}
	if code, body := postJSON(t, h.AdminVacuumCancel, "/unmask/admin/api/vacuum/cancel", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("cancel: %d %v", code, body)
	}
	waitFor(t, "the run to end", 20*time.Second, func() bool {
		h.VacuumRefresh(context.Background())
		return !h.VacuumGoing() && !h.DB.WritesHeld()
	})
	rec, ok, _ := h.DB.LoadVacuum(context.Background())
	if !ok || rec.State != db.VacuumCancelled {
		t.Errorf("record = %+v, want cancelled", rec)
	}
	if after := fileSizeOf(t, h.DB.SQLitePath); after != before {
		t.Errorf("a cancelled run changed the file: %d -> %d", before, after)
	}
	if v := h.vacuumView(user.RoleSuperadmin, i18n.LangEN); v == nil || v.State != "cancelled" {
		t.Errorf("view after = %+v", v)
	}
	if code, _ := postJSON(t, h.AdminVacuumCancel, "/unmask/admin/api/vacuum/cancel", user.RoleSuperadmin); code != http.StatusConflict {
		t.Errorf("cancel with nothing running: %d, want 409", code)
	}
}

// A run typed into a shell: the daemon did not start it, sees it by its lock,
// holds its writes and hands over -- the run waits for that before it takes
// the write lock -- and lets go when the run ends.
func TestVacuumRunFromAShell(t *testing.T) {
	h := vacuumHandler(t, 2000)
	cmd := exec.Command(os.Args[0], vacuumHelperArgs...)
	cmd.Env = vacuumHelperEnv(h, 800*time.Millisecond, db.VacuumByCLI)
	out := &logLines{prefix: "shell run: "}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	waitFor(t, "the daemon to hand over to the run", 20*time.Second, func() bool {
		h.VacuumRefresh(context.Background())
		return h.DB.VacuumHeldFor(cmd.Process.Pid)
	})
	if !h.DB.WritesHeldForVacuum() {
		t.Error("handed over without holding the writes")
	}
	// The helper is this test binary, no `db-vacuum` process: the daemon
	// does not signal it, and says where it can be stopped.
	if v := h.vacuumView(user.RoleSuperadmin, i18n.LangEN); v == nil || v.State != "running" || v.Cancellable || v.CanCancel ||
		v.By != db.VacuumByCLI || v.StopHint != i18n.Tf(i18n.LangEN, "vacuum.stop_hint_shell", cmd.Process.Pid) {
		t.Errorf("view of a run from a shell = %+v (not one to signal)", v)
	}
	if _, err := h.vacuumCancel(); err != errVacuumNotOurs {
		t.Errorf("cancel of a process that is no db-vacuum: %v, want errVacuumNotOurs", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the run: %v (%s)", err, out.tail())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not end")
	}
	h.VacuumRefresh(context.Background())
	if h.DB.WritesHeld() || h.VacuumGoing() {
		t.Error("the writes are still held after the run ended")
	}
	if rec, ok, _ := h.DB.LoadVacuum(context.Background()); !ok || rec.State != db.VacuumDone {
		t.Errorf("record = %+v", rec)
	}
}

// A run typed into a shell can be stopped from the card too: the daemon makes
// sure the process on record is a `db-vacuum` it may signal, and sends it what
// Ctrl-C would.  The run rolls back and records itself as cancelled, and the
// stop is in the audit log once the writes are let go.
func TestVacuumCancelARunFromAShell(t *testing.T) {
	h := vacuumHandler(t, 2000)
	before := fileSizeOf(t, h.DB.SQLitePath)
	// A trailing "db-vacuum" makes the helper's command line read as a run's
	// (the test binary takes it as a positional argument and ignores it).
	cmd := exec.Command(os.Args[0], append(append([]string{}, vacuumHelperArgs...), "db-vacuum")...)
	cmd.Env = vacuumHelperEnv(h, time.Minute, db.VacuumByCLI)
	out := &logLines{prefix: "shell run: "}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	waitFor(t, "the daemon to hand over to the run", 20*time.Second, func() bool {
		h.VacuumRefresh(context.Background())
		return h.DB.VacuumHeldFor(cmd.Process.Pid)
	})
	waitFor(t, "the run's record", 20*time.Second, func() bool {
		h.VacuumRefresh(context.Background())
		rec, ok, _ := h.DB.LoadVacuum(context.Background())
		return ok && rec.State == db.VacuumRunning && rec.PID == cmd.Process.Pid
	})
	v := h.vacuumView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || !v.Cancellable || !v.CanCancel || v.StopHint != "" {
		t.Fatalf("superadmin's view of a db-vacuum from a shell = %+v, want it stoppable", v)
	}
	if body := renderTab(t, h, "retention", user.RoleSuperadmin, "en"); !strings.Contains(body, `id="vacuum-cancel"`) ||
		!strings.Contains(body, i18n.T(i18n.LangEN, "vacuum.cancel_note")) {
		t.Error("the card of a run from a shell has no cancel button, or does not say what a stop does")
	}
	if a := h.vacuumView(user.RoleAdmin, i18n.LangEN); a == nil || a.Cancellable || a.StopHint != i18n.T(i18n.LangEN, "vacuum.stop_hint_role") {
		t.Errorf("admin's view = %+v", a)
	}
	if code, body := postJSON(t, h.AdminVacuumCancel, "/unmask/admin/api/vacuum/cancel", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("cancel: %d %v", code, body)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not stop")
	}
	waitFor(t, "the writes to be let go", 20*time.Second, func() bool {
		h.VacuumRefresh(context.Background())
		return !h.VacuumGoing() && !h.DB.WritesHeld()
	})
	if rec, ok, _ := h.DB.LoadVacuum(context.Background()); !ok || rec.State != db.VacuumCancelled {
		t.Errorf("record = %+v, want cancelled", rec)
	}
	if after := fileSizeOf(t, h.DB.SQLitePath); after != before {
		t.Errorf("a cancelled run changed the file: %d -> %d", before, after)
	}
	waitFor(t, "the stop in the audit log", 5*time.Second, func() bool {
		var n int
		err := h.DB.QueryRow(`SELECT COUNT(*) FROM unmask_user_audit WHERE action = 'db.vacuum.cancel' AND target = ?`, db.VacuumByCLI).Scan(&n)
		return err == nil && n == 1
	})
}

// Once VACUUM has committed, the run moves the database out of the
// write-ahead log: a stop would neither undo nor shorten that, so the card
// offers none and says why, and a stop asked for anyway is refused.
func TestVacuumNoCancelAtTheCheckpoint(t *testing.T) {
	h := vacuumHandler(t, 10)
	lock, err := h.DB.LockVacuumRun(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	rec := db.VacuumRecord{State: db.VacuumRunning, PID: os.Getpid(), By: "alice", Host: "test-host", Stats: true,
		StartedAt: time.Now().Add(-time.Hour).Unix(), LiveBefore: 1 << 30, DiskFreeAtStart: 100 << 30, Stage: db.VacuumStageCheckpoint}
	if err := h.DB.SaveMaintState(context.Background(), db.MaintVacuum, rec); err != nil {
		t.Fatal(err)
	}
	h.VacuumRefresh(context.Background())
	v := h.vacuumView(user.RoleSuperadmin, i18n.LangJA)
	if v == nil || v.Phase != db.VacuumStageCheckpoint || v.Progress != -1 || v.CanCancel || v.StopHint != "" ||
		v.CancelNote != i18n.T(i18n.LangJA, "vacuum.cancel_note_checkpoint") || v.StepText != i18n.T(i18n.LangJA, "vacuum.phase_checkpoint") {
		t.Fatalf("view at the checkpoint = %+v", v)
	}
	// Four steps with the statistics: the copy and the write-back done, the
	// checkpoint going with no figure, the statistics to come.
	want := []VacuumStepBar{{"copy", 100, false, false}, {"write", 100, false, false},
		{db.VacuumStageCheckpoint, 100, true, true}, {db.VacuumStageStats, 0, false, false}}
	if fmt.Sprint(v.Bars) != fmt.Sprint(want) {
		t.Errorf("bars = %+v, want %+v", v.Bars, want)
	}
	if _, err := h.vacuumCancel(); err != errVacuumCommitted {
		t.Errorf("cancel at the checkpoint: %v, want errVacuumCommitted", err)
	}
}

// The time a step has left is read off the run's own speed: the copy's from
// the start of the run, the write-back's from the daemon's first sight of it,
// and the checkpoint's from the write-back's (it copies the same data).
func TestVacuumTimeLeft(t *testing.T) {
	t0 := time.Now()
	rec := db.VacuumRecord{State: db.VacuumRunning, StartedAt: t0.Add(-10 * time.Minute).Unix()}
	var v vacuumRunner
	if _, ok := v.timeLeft(rec, t0); ok {
		t.Error("a time left before any reading")
	}
	// 30% copied in ten minutes: 70% more at that speed.
	v.observe(rec, db.VacuumStep{Phase: "copy", Done: 300, Total: 1000}, t0)
	if d, ok := v.timeLeft(rec, t0); !ok || d < 23*time.Minute || d > 24*time.Minute {
		t.Errorf("copy: %v %v, want about 23m20s", d, ok)
	}
	if d, _ := v.timeLeft(rec, t0.Add(20*time.Minute)); d > 4*time.Minute {
		t.Errorf("copy, twenty minutes after the reading: %v, want what is left of it", d)
	}
	// The write-back: from the first sight of it, 300 bytes a minute.
	w := t0.Add(time.Minute)
	v.observe(rec, db.VacuumStep{Phase: "write", Done: 100, Total: 1000}, w)
	if _, ok := v.timeLeft(rec, w); ok {
		t.Error("a time left at the first sight of the write-back")
	}
	v.observe(rec, db.VacuumStep{Phase: "write", Done: 400, Total: 1000}, w.Add(time.Minute))
	if d, ok := v.timeLeft(rec, w.Add(time.Minute)); !ok || d != 2*time.Minute {
		t.Errorf("write-back: %v %v, want 2m", d, ok)
	}
	// The checkpoint, at the write-back's speed: 1000 bytes at 5 a second.
	c := w.Add(3 * time.Minute)
	v.observe(rec, db.VacuumStep{Phase: db.VacuumStageCheckpoint}, c)
	if d, ok := v.timeLeft(rec, c.Add(50*time.Second)); !ok || d != 150*time.Second {
		t.Errorf("checkpoint: %v %v, want 2m30s", d, ok)
	}
	if _, ok := v.timeLeft(rec, c.Add(10*time.Minute)); ok {
		t.Error("a time left past the checkpoint's own: no figure rather than a wrong one")
	}
	v.observe(rec, db.VacuumStep{Phase: db.VacuumStageStats}, c.Add(time.Minute))
	if _, ok := v.timeLeft(rec, c.Add(time.Minute)); ok {
		t.Error("a time left for the statistics, which no file measures")
	}
	// Another run starts over.
	next := rec
	next.StartedAt = t0.Unix()
	v.observe(next, db.VacuumStep{Phase: "copy", Done: 10, Total: 1000}, t0.Add(30*time.Second))
	if v.writeRate != 0 {
		t.Error("the last run's write-back speed carried over")
	}
}

// What the card says of the held events, and of a time ahead.
func TestVacuumHeldAndAboutText(t *testing.T) {
	if s, near := heldText(i18n.LangJA, 41234, 810906, 30*time.Minute); near || s != "保留中のイベント 41,234 件 (上限 810,906 件。いまの流量なら上限まで約 9 時間 20 分)" {
		t.Errorf("held = %q, %v", s, near)
	}
	if s, near := heldText(i18n.LangEN, 760000, 810906, time.Hour); !near || !strings.Contains(s, "oldest are dropped") {
		t.Errorf("held near the limit = %q, %v", s, near)
	}
	if s, _ := heldText(i18n.LangEN, 10, 50000, 20*time.Second); s != "10 events held (the limit is 50,000)." {
		t.Errorf("held in the first minute = %q", s)
	}
	for _, c := range []struct {
		d      time.Duration
		ja, en string
	}{
		{40 * time.Second, "1 分未満", "under a minute"},
		{33*time.Minute + 20*time.Second, "約 33 分", "about 33 min"},
		{70 * time.Minute, "約 70 分", "about 70 min"},
		{2*time.Hour + 4*time.Minute, "約 2 時間 5 分", "about 2 h 5 min"},
		{3*time.Hour + 59*time.Minute, "約 4 時間", "about 4 h"},
		{11*time.Hour + 9*time.Minute, "約 11 時間", "about 11 h"},
		{170 * time.Hour, "約 7 日", "about 7 days"},
	} {
		if got := aboutText(i18n.LangJA, c.d); got != c.ja {
			t.Errorf("aboutText(ja, %v) = %q, want %q", c.d, got, c.ja)
		}
		if got := aboutText(i18n.LangEN, c.d); got != c.en {
			t.Errorf("aboutText(en, %v) = %q, want %q", c.d, got, c.en)
		}
	}
}

// A run whose process is gone -- killed, its host rebooted -- leaves a record
// saying "running" and a free lock: the daemon holds nothing for it and says
// it was interrupted.
func TestVacuumRunKilled(t *testing.T) {
	h := vacuumHandler(t, 10)
	rec := db.VacuumRecord{State: db.VacuumRunning, PID: 999999, By: "cli", StartedAt: time.Now().Add(-time.Minute).Unix(), EstHighSec: 600}
	if err := h.DB.SaveMaintState(context.Background(), db.MaintVacuum, rec); err != nil {
		t.Fatal(err)
	}
	h.VacuumRefresh(context.Background())
	if h.DB.WritesHeld() || h.VacuumGoing() {
		t.Error("a dead run holds the writes")
	}
	v := h.vacuumView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "failed" || !strings.Contains(v.Err, "interrupted") {
		t.Errorf("view = %+v, want failed (interrupted)", v)
	}
}

// renderTab renders one tab of the settings page, the way the router hands
// the handler its path value.
func renderTab(t *testing.T, h *Handler, tab, role, lang string) string {
	t.Helper()
	req := asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/"+tab+"/", nil), role)
	req.SetPathValue("tab", tab)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: lang})
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("settings/%s as %s: status %d", tab, role, rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "</html>") {
		t.Fatalf("settings/%s as %s: the page is cut short (no </html>): a template error", tab, role)
	}
	return body
}

// The retention tab's card: the plan's figures, and the button only where a
// run is worth it and allowed -- with the reason when it is not.
func TestVacuumCardOnTheRetentionTab(t *testing.T) {
	h := vacuumHandler(t, 400)
	for _, c := range []struct {
		role, lang string
		want       []string
	}{
		{user.RoleSuperadmin, "en", []string{`id="vacuum-card"`, `data-vacuum="size"`, `data-vacuum="disk"`, `data-vacuum="time"`, `data-vacuum="held"`,
			`data-vacuum="mem"`, "Database compaction", i18n.T(i18n.LangEN, "vacuum.blocked_little"), `id="vacuum-run" disabled`,
			// The button asks in a modal of the card's own, not with confirm().
			`id="vacuum-dialog"`, i18n.T(i18n.LangEN, "vacuum.dialog_h"), i18n.T(i18n.LangEN, "vacuum.dialog_note_edits")}},
		{user.RoleAdmin, "ja", []string{`id="vacuum-card"`, "データベースの圧縮", i18n.T(i18n.LangJA, "vacuum.needs_superadmin")}},
	} {
		body := renderTab(t, h, "retention", c.role, c.lang)
		for _, w := range c.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s/%s: the retention tab lacks %q", c.role, c.lang, w)
			}
		}
	}
	// The events held over the run are an estimate, with how long the
	// daemon can hold them at the recent rate.
	if body := renderTab(t, h, "retention", user.RoleSuperadmin, "en"); !strings.Contains(body, "the high end of the estimate") ||
		!strings.Contains(body, " at this rate)") || strings.Contains(body, "up to about") {
		t.Error("the plan's held events: not worded as an estimate with how long the hold lasts")
	}
	// Not on another tab.
	if body := renderTab(t, h, "network", user.RoleSuperadmin, "en"); strings.Contains(body, `id="vacuum-card"`) {
		t.Error("the compaction card is on the network tab")
	}
	// The memory the hold takes counts the access-log counters only where
	// the access-log integration keeps them.
	counters := strings.SplitN(i18n.T(i18n.LangEN, "vacuum.mem_basis"), "%", 2)[0]
	if body := renderTab(t, h, "retention", user.RoleSuperadmin, "en"); strings.Contains(body, counters) {
		t.Error("access-log counters in the hold's memory with the access-log integration off")
	}
	st := h.SnapshotSettings()
	st.NginxLog.Enabled = true
	h.SetSettings(st)
	if body := renderTab(t, h, "retention", user.RoleSuperadmin, "en"); !strings.Contains(body, counters) {
		t.Error("no access-log counters in the hold's memory with the access-log integration on")
	}
	// After a run, the card says how the last one went.
	if err := h.DB.SaveMaintState(context.Background(), db.MaintVacuum, db.VacuumRecord{State: db.VacuumDone, By: "alice",
		StartedAt: time.Now().Add(-time.Hour).Unix(), EndedAt: time.Now().Add(-50 * time.Minute).Unix(),
		FileBefore: 36 << 30, FileAfter: 16 << 30, Seconds: 600}); err != nil {
		t.Fatal(err)
	}
	body := renderTab(t, h, "retention", user.RoleSuperadmin, "en")
	if !strings.Contains(body, `id="vacuum-last" data-ended="`) || !strings.Contains(body, "36.00 GB") || !strings.Contains(body, "16.00 GB") {
		t.Error("the card does not show the last run")
	}
}

// The top bar's sign of a run is on every page while it goes, and on none
// when there has been no run.  The run in full is on the retention tab's card
// alone, which that tab has in place of the sign.
func TestVacuumNoticeOnEveryPage(t *testing.T) {
	h := vacuumHandler(t, 10)
	for path, fn := range pagesWithTheHeader(h) {
		if body := renderAs(t, fn, path, user.RoleSuperadmin, "en"); strings.Contains(body, `id="vacpill"`) {
			t.Errorf("%s: a compaction sign with no run", path)
		}
	}
	lock, err := h.DB.LockVacuumRun(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	rec := db.VacuumRecord{State: db.VacuumRunning, PID: os.Getpid(), By: "alice", Host: "test-host",
		StartedAt: time.Now().Unix(), EstLowSec: 600, EstHighSec: 1800, LiveBefore: 1 << 30, FileBefore: 2 << 30, DiskFreeAtStart: 100 << 30}
	if err := h.DB.SaveMaintState(context.Background(), db.MaintVacuum, rec); err != nil {
		t.Fatal(err)
	}
	h.VacuumRefresh(context.Background())
	for path, fn := range pagesWithTheHeader(h) {
		for _, lang := range []string{"en", "ja"} {
			body := renderAs(t, fn, path, user.RoleAdmin, lang)
			if !strings.Contains(body, `id="vacpill"`) || !strings.Contains(body, `data-state="running"`) {
				t.Errorf("%s (%s): no sign of the running compaction in the top bar", path, lang)
			}
			// "Compacting DB: copy 12%": the words before the step.
			if w, _, _ := strings.Cut(i18n.T(i18n.Lang(lang), "vacuum.pill_running"), " %"); !strings.Contains(body, w) {
				t.Errorf("%s (%s): the sign does not say a compaction is running", path, lang)
			}
			if !strings.Contains(body, "/admin/settings/retention/#vacuum-card") {
				t.Errorf("%s (%s): the sign does not lead to the card", path, lang)
			}
			// No banner across the page: the details are the card's.
			if strings.Contains(body, i18n.T(i18n.Lang(lang), "vacuum.running_sub")) {
				t.Errorf("%s (%s): the run's details are on a page other than the card", path, lang)
			}
		}
	}
	// The retention tab: the run in the card -- who started it, as this
	// daemon did not -- and no sign in the top bar repeating it.  The write
	// check above the card names the compaction as what holds the writes.
	body := renderTab(t, h, "retention", user.RoleSuperadmin, "en")
	for _, w := range []string{`id="vacuum-progress"`, i18n.Tf(i18n.LangEN, "vacuum.started_by", "alice", "test-host"),
		i18n.T(i18n.LangEN, "settings.retention.write_held_vacuum")} {
		if !strings.Contains(body, w) {
			t.Errorf("the retention tab lacks %q while a run goes", w)
		}
	}
	// The run on record is this test's own process, no db-vacuum to signal.
	if strings.Contains(body, `id="vacpill"`) || strings.Contains(body, `id="vacuum-cancel"`) {
		t.Error("the retention tab: a sign in the top bar, or a cancel button for a process that is no db-vacuum")
	}
	// A change that writes to the database is refused with a compaction's
	// words, not a schema update's.
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/api/users/new", nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.respondWritesHeld(rr, req)
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "compacted") {
		t.Errorf("refused change: %d %s", rr.Code, rr.Body.String())
	}
}

// The events held are the rate over the high end of the estimate, which the
// card words as the estimate's range rounds it.
func TestUpToTextRoundsLikeTheEstimate(t *testing.T) {
	for _, c := range []struct {
		d      time.Duration
		en, ja string
	}{
		{0, "10 s", "10 秒"},
		{8 * time.Second, "10 s", "10 秒"},
		{85 * time.Second, "90 s", "90 秒"},
		{90 * time.Second, "2 min", "2 分"},
		{264 * time.Second, "5 min", "5 分"},
		{80 * time.Minute, "80 min", "80 分"},
	} {
		if got := upToText(i18n.LangEN, c.d); got != c.en {
			t.Errorf("upToText(en, %v) = %q, want %q", c.d, got, c.en)
		}
		if got := upToText(i18n.LangJA, c.d); got != c.ja {
			t.Errorf("upToText(ja, %v) = %q, want %q", c.d, got, c.ja)
		}
		// The estimate's own words for the same high end end in the same figure.
		if r := db.EstimateRange(c.d, c.d); c.d >= 10*time.Second && !strings.HasSuffix(r, c.en) {
			t.Errorf("EstimateRange(%v) = %q; the card's %q does not match it", c.d, r, c.en)
		}
	}
}

// A database without the query planner's statistics: the card says the run
// builds them after the compaction, and so does the modal; with them, neither
// does.  While they are built the progress line says so, as the last of four
// steps -- the files the percentages are read from say nothing of it.
func TestVacuumCardSaysItBuildsTheStatistics(t *testing.T) {
	h := vacuumHandler(t, 400)
	ctx := context.Background()
	note := i18n.T(i18n.LangEN, "vacuum.dialog_note_stats")
	body := renderTab(t, h, "retention", user.RoleSuperadmin, "en")
	if !strings.Contains(body, `data-vacuum="stats"`) || !strings.Contains(body, i18n.T(i18n.LangEN, "vacuum.stats_value")) || !strings.Contains(body, note) {
		t.Error("no word on the card or in the modal that the run builds the missing statistics")
	}
	if err := h.DB.RefreshPlannerStats(ctx); err != nil {
		t.Fatal(err)
	}
	body = renderTab(t, h, "retention", user.RoleSuperadmin, "ja")
	if strings.Contains(body, `data-vacuum="stats"`) || strings.Contains(body, i18n.T(i18n.LangJA, "vacuum.dialog_note_stats")) {
		t.Error("the card offers to build statistics that exist")
	}

	lock, err := h.DB.LockVacuumRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	rec := db.VacuumRecord{State: db.VacuumRunning, PID: os.Getpid(), By: "alice", Host: "elsewhere",
		StartedAt: time.Now().Add(-time.Minute).Unix(), EstLowSec: 60, EstHighSec: 180, LiveBefore: 1 << 30, FileBefore: 2 << 30,
		DiskFreeAtStart: 100 << 30, Stage: db.VacuumStageStats}
	if err := h.DB.SaveMaintState(ctx, db.MaintVacuum, rec); err != nil {
		t.Fatal(err)
	}
	h.VacuumRefresh(ctx)
	body = renderTab(t, h, "retention", user.RoleAdmin, "ja")
	if !strings.Contains(body, `<span id="vacuum-step">`+i18n.T(i18n.LangJA, "vacuum.phase_stats")+`</span>`) {
		t.Error("the progress line does not say the statistics are being built")
	}
	if !strings.Contains(body, `class="vacuum-step is-current is-busy" data-step="stats"`) {
		t.Error("the statistics are not the step going, drawn with no figure")
	}
	// The page's poll gets the words from the status, in the reader's
	// language.
	req := asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/api/vacuum", nil), user.RoleAdmin)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "ja"})
	rr := httptest.NewRecorder()
	h.AdminVacuumStatus(rr, req)
	var v VacuumView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil || v.State != "running" || v.Phase != "stats" || v.Progress != -1 ||
		v.Steps != 4 || v.StepText != i18n.T(i18n.LangJA, "vacuum.phase_stats") || v.CancelNote != i18n.T(i18n.LangJA, "vacuum.cancel_note_stats") {
		t.Errorf("status at the statistics stage = %s (%v)", rr.Body.String(), err)
	}
}
