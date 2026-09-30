package handlers

import (
	"context"
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
	v := h.vacuumView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "running" || !v.CanCancel || v.StartedAt == 0 || v.By == "" {
		t.Fatalf("view while running = %+v", v)
	}
	if other := h.vacuumView(user.RoleAdmin, i18n.LangEN); other == nil || other.State != "running" || other.CanCancel {
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
	// The card has the run where its button was, with the cancel button for
	// the superadmin whose daemon started it.
	body := renderTab(t, h, "retention", user.RoleSuperadmin, "en")
	for _, w := range []string{`id="vacuum-progress"`, `id="vacuum-cancel"`, i18n.T(i18n.LangEN, "vacuum.running_sub")} {
		if !strings.Contains(body, w) {
			t.Errorf("the card of a running compaction lacks %q", w)
		}
	}
	if strings.Contains(body, `id="vacuum-run"`) {
		t.Error("the card offers to start a compaction while one runs")
	}
	if body := renderTab(t, h, "retention", user.RoleAdmin, "en"); !strings.Contains(body, `id="vacuum-progress"`) || strings.Contains(body, `id="vacuum-cancel"`) {
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
	if v := h.vacuumView(user.RoleSuperadmin, i18n.LangEN); v == nil || v.State != "running" || v.CanCancel || v.By != db.VacuumByCLI {
		t.Errorf("view of a run from a shell = %+v (not ours to cancel)", v)
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
			"Database compaction", i18n.T(i18n.LangEN, "vacuum.blocked_little"), `id="vacuum-run" disabled`}},
		{user.RoleAdmin, "ja", []string{`id="vacuum-card"`, "データベースの圧縮", i18n.T(i18n.LangJA, "vacuum.needs_superadmin")}},
	} {
		body := renderTab(t, h, "retention", c.role, c.lang)
		for _, w := range c.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s/%s: the retention tab lacks %q", c.role, c.lang, w)
			}
		}
	}
	// Not on another tab.
	if body := renderTab(t, h, "network", user.RoleSuperadmin, "en"); strings.Contains(body, `id="vacuum-card"`) {
		t.Error("the compaction card is on the network tab")
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
			// "Compacting DB 12%": the words before the figure.
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
	if strings.Contains(body, `id="vacpill"`) || strings.Contains(body, `id="vacuum-cancel"`) {
		t.Error("the retention tab: a sign in the top bar, or a cancel button for a run from a shell")
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
