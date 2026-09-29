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

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/captcha"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// schemaHandler is a handler over a database that was migrated the way an
// install's is, holding n events, with the fingerprint index migrations
// (0032, 0033) undone: an install that has just been upgraded across them.
// deferOver is the daemon's threshold; a millisecond makes the index build one
// the daemon leaves for the operator, however small the table.
func schemaHandler(t *testing.T, n int, deferOver float64) *Handler {
	t.Helper()
	cfg := settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "s.sqlite"), SchemaUpdateDeferSeconds: deferOver}
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
		if _, err := tx.Exec(`INSERT INTO unmask_event (site, host, ip_address, ja4, phase, date_created)
			VALUES ('s', 'h', X'0A000001', ?, 'serve', CURRENT_TIMESTAMP)`, fmt.Sprintf("t13d%04d", i%97)); err != nil {
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
		if _, err := conn.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.RefreshIndexes(context.Background()); err != nil {
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

func asRole(r *http.Request, role string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, &SessionPayload{UserID: 1, Role: role}))
}

func indexThere(t *testing.T, h *Handler) bool {
	t.Helper()
	var n int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_unmask_event_ja4_phase'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// TestSchemaViewNothingWaiting: nearly every install.  No view, so no notice
// and nothing for the page to render.
func TestSchemaViewNothingWaiting(t *testing.T) {
	h := schemaHandler(t, 50, 0) // the default threshold: 50 rows build in no time
	// What the daemon does at startup.
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	h.SchemaRefresh(context.Background())
	if v := h.schemaView(user.RoleSuperadmin, i18n.LangEN); v != nil {
		t.Fatalf("view = %+v, want none", v)
	}
	if n, running := h.SchemaWaiting(); n != 0 || running {
		t.Errorf("waiting=%d running=%v", n, running)
	}
	if h.DB.WritesHeld() {
		t.Error("writes held with nothing going on")
	}
	if !indexThere(t, h) {
		t.Error("a small table's index is built at startup")
	}
}

// TestSchemaViewPending: an update waits.  Everyone who signs in sees it; the
// button is the superadmin's.
func TestSchemaViewPending(t *testing.T) {
	h := schemaHandler(t, 200, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	h.SchemaRefresh(context.Background())
	if indexThere(t, h) {
		t.Fatal("the index was built at startup although it was to be deferred")
	}
	super := h.schemaView(user.RoleSuperadmin, i18n.LangEN)
	if super == nil || super.State != "pending" || !super.CanRun || super.CanCancel {
		t.Fatalf("superadmin view = %+v", super)
	}
	if super.Est == "" {
		t.Error("the notice must say how long the update is expected to take")
	}
	for _, role := range []string{user.RoleAdmin, user.RoleViewer} {
		v := h.schemaView(role, i18n.LangEN)
		if v == nil || v.State != "pending" {
			t.Fatalf("%s view = %+v, want the notice", role, v)
		}
		if v.CanRun || v.CanCancel {
			t.Errorf("%s may run=%v cancel=%v; starting a schema update takes a superadmin", role, v.CanRun, v.CanCancel)
		}
	}
	if n, running := h.SchemaWaiting(); n != 2 || running {
		t.Errorf("waiting=%d running=%v, want the two index migrations", n, running)
	}
	if h.DB.WritesHeld() {
		t.Error("writes are held while the update only waits")
	}
}

func TestEstimateText(t *testing.T) {
	for _, c := range []struct {
		lo, hi time.Duration
		en, ja string
	}{
		{0, 0, "no time", "ほぼ 0 秒"},
		{time.Second, 3 * time.Second, "under 10 s", "10 秒未満"},
		{25 * time.Second, 28 * time.Second, "about 30 s", "約 30 秒"},
		{12 * time.Second, 36 * time.Second, "20-40 s", "20〜40 秒"},
		{4 * time.Minute, 10 * time.Minute, "4-10 min", "4〜10 分"},
		{9*time.Minute + time.Second, 10 * time.Minute, "about 10 min", "約 10 分"},
	} {
		if got := estimateText(i18n.LangEN, c.lo, c.hi); got != c.en {
			t.Errorf("en(%v, %v) = %q, want %q", c.lo, c.hi, got, c.en)
		}
		if got := estimateText(i18n.LangJA, c.lo, c.hi); got != c.ja {
			t.Errorf("ja(%v, %v) = %q, want %q", c.lo, c.hi, got, c.ja)
		}
	}
	if got := durationText(i18n.LangEN, 232); got != "3 min 52 s" {
		t.Errorf("durationText en = %q", got)
	}
	if got := durationText(i18n.LangJA, 52); got != "52 秒" {
		t.Errorf("durationText ja = %q", got)
	}
}

// TestSchemaUpdateHelper is not a test: it is the process the tests below
// start in place of `unmask migrate`, selected by an environment variable so
// that an ordinary run of the suite skips it.  It does what that command does
// -- applies the pending schema update with a record, stopping when it is
// signalled -- after holding the write lock for a while, the way a build over
// a large table does.
func TestSchemaUpdateHelper(t *testing.T) {
	path := os.Getenv("UNMASK_TEST_SCHEMA_DB")
	if path == "" {
		t.Skip("helper process for the schema update tests")
	}
	hold, _ := time.ParseDuration(os.Getenv("UNMASK_TEST_SCHEMA_HOLD"))
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: path})
	if err != nil {
		fmt.Println("helper: open:", err)
		os.Exit(3)
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	opt := db.SchemaUpdateOptions{Host: os.Getenv("UNMASK_TEST_SCHEMA_HOST"), By: os.Getenv("UNMASK_TEST_SCHEMA_BY"),
		Logf: func(f string, a ...any) { fmt.Printf(f+"\n", a...) }}
	if hold > 0 {
		// The run's record, then the write lock, held.
		rec := db.SchemaUpdateRecord{State: db.SchemaUpdateRunning, Host: opt.Host, By: opt.By, PID: os.Getpid(),
			Items: []string{"0032_event_ja4_index"}, StartedAt: time.Now().Unix(), EstLowSec: 60, EstHighSec: 180}
		if err := conn.SaveMaintState(ctx, db.MaintSchemaUpdate, rec); err != nil {
			fmt.Println("helper: record:", err)
			os.Exit(3)
		}
		c, err := conn.Conn(ctx)
		if err != nil {
			os.Exit(3)
		}
		if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			fmt.Println("helper: lock:", err)
			os.Exit(3)
		}
		select {
		case <-time.After(hold):
		case <-ctx.Done():
		}
		_, _ = c.ExecContext(context.Background(), "ROLLBACK")
		_ = c.Close()
		if ctx.Err() != nil {
			rec.State, rec.Err, rec.EndedAt = db.SchemaUpdateCancelled, "cancelled", time.Now().Unix()
			_ = conn.SaveMaintState(context.Background(), db.MaintSchemaUpdate, rec)
			fmt.Println("helper: cancelled")
			os.Exit(1)
		}
	}
	if _, err := db.ApplySchemaUpdate(ctx, conn, opt); err != nil {
		fmt.Println("helper:", err)
		os.Exit(1)
	}
	fmt.Println("schema applied")
	os.Exit(0)
}

// helperCommand makes h start TestSchemaUpdateHelper where it would start
// `unmask migrate`.
func helperCommand(h *Handler, hold time.Duration) {
	h.SchemaCommand = func(by string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSchemaUpdateHelper$")
		cmd.Env = append(os.Environ(),
			"UNMASK_TEST_SCHEMA_DB="+h.cfg().DB.SQLitePath,
			"UNMASK_TEST_SCHEMA_HOLD="+hold.String(),
			"UNMASK_TEST_SCHEMA_HOST="+h.HostID,
			"UNMASK_TEST_SCHEMA_BY="+by,
		)
		return cmd, nil
	}
}

// waitForRecord waits until the run has written its record: from then on it
// handles a signal itself, and the daemon knows who started it.
func waitForRecord(t *testing.T, h *Handler) {
	t.Helper()
	waitFor(t, "the run's record", 20*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		rec, ok, err := h.DB.LoadSchemaUpdate(context.Background())
		return err == nil && ok && rec.State == db.SchemaUpdateRunning && rec.Alive(h.HostID, time.Now())
	})
}

func waitFor(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func postJSON(t *testing.T, fn http.HandlerFunc, path, role string) (int, map[string]any) {
	t.Helper()
	req := asRole(httptest.NewRequest(http.MethodPost, path, nil), role)
	rr := httptest.NewRecorder()
	fn(rr, req)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

// TestSchemaUpdateRunFromTheUI: the button.  The update runs as a process of
// its own; while it holds the write lock the daemon's writers stand back, the
// events that arrive are kept, and a change in the admin UI is answered with
// why it cannot be made; afterwards the index is there, the events are
// written, and the notice says the update finished.
func TestSchemaUpdateRunFromTheUI(t *testing.T) {
	h := schemaHandler(t, 300, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	helperCommand(h, 1500*time.Millisecond)
	fl := events.NewFlusher(h.DB, 10, 50)
	defer fl.Stop()
	countEvents := func() int {
		var n int
		if err := h.DB.QueryRow(`SELECT COUNT(*) FROM unmask_event WHERE phase = 'load'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	h.SchemaRefresh(context.Background())
	code, body := postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin)
	if code != http.StatusOK {
		t.Fatalf("run: %d %v", code, body)
	}
	if !h.DB.WritesHeld() {
		t.Fatal("writes must be held from the moment the run is started, before its record can be seen")
	}
	// A second press while it runs is refused.
	if code, _ := postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin); code != http.StatusConflict {
		t.Errorf("second run: %d, want 409", code)
	}

	// While it runs.
	waitForRecord(t, h)
	v := h.schemaView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "running" || !v.CanCancel || v.CanRun {
		t.Fatalf("view while running = %+v", v)
	}
	if v.StartedAt == 0 || v.By == "" {
		t.Errorf("the running notice carries no start time or starter: %+v", v)
	}
	if other := h.schemaView(user.RoleAdmin, i18n.LangEN); other == nil || other.State != "running" || other.CanCancel {
		t.Errorf("admin view while running = %+v", other)
	}
	for i := 0; i < 25; i++ {
		fl.Submit(&events.Event{Site: "s", IPPacked: []byte{10, 0, 0, 9}, Phase: "load"})
	}
	time.Sleep(300 * time.Millisecond)
	if n := countEvents(); n != 0 {
		t.Errorf("%d events were written against the held lock; they are to be kept", n)
	}

	// Afterwards.
	waitFor(t, "the run to end", 15*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		_, running := h.SchemaWaiting()
		return !running && !h.DB.WritesHeld()
	})
	if !indexThere(t, h) {
		t.Fatal("the index is not there after the run")
	}
	if got := h.DB.EventJA4IndexHint(); got == "" {
		t.Error("the index hint did not come back: the daemon must re-read the index list when a run ends")
	}
	waitFor(t, "the kept events to be written", 5*time.Second, func() bool { return countEvents() == 25 })
	if n, running := h.SchemaWaiting(); n != 0 || running {
		t.Errorf("after the run: waiting=%d running=%v", n, running)
	}
	rec, ok, err := h.DB.LoadSchemaUpdate(context.Background())
	if err != nil || !ok || rec.State != db.SchemaUpdateDone {
		t.Fatalf("record = (%+v, %v, %v)", rec, ok, err)
	}
}

// TestSchemaUpdateCancel: the run is stopped; the update is pending again, and
// the notice says the last one was cancelled.
func TestSchemaUpdateCancel(t *testing.T) {
	h := schemaHandler(t, 300, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	helperCommand(h, 30*time.Second)
	h.SchemaRefresh(context.Background())

	// Nothing to cancel before it is started.
	if code, _ := postJSON(t, h.AdminSchemaUpdateCancel, "/unmask/admin/api/schema-update/cancel", user.RoleSuperadmin); code != http.StatusConflict {
		t.Errorf("cancel with nothing running: %d, want 409", code)
	}
	if code, body := postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("run: %d %v", code, body)
	}
	waitForRecord(t, h)
	if code, body := postJSON(t, h.AdminSchemaUpdateCancel, "/unmask/admin/api/schema-update/cancel", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("cancel: %d %v", code, body)
	}
	waitFor(t, "the run to stop", 10*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		_, running := h.SchemaWaiting()
		return !running && !h.DB.WritesHeld()
	})
	if indexThere(t, h) {
		t.Fatal("a cancelled run built the index")
	}
	v := h.schemaView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "pending" || !v.Cancelled || !v.CanRun {
		t.Fatalf("view after cancel = %+v, want pending, marked cancelled, and runnable again", v)
	}
}

// TestSchemaRunStartedElsewhere: `unmask migrate` typed into a shell.  The
// daemon did not start it, and has to notice it all the same: hold its
// writes, show the notice, and offer no cancel button for a process that is
// not its own.
func TestSchemaRunStartedElsewhere(t *testing.T) {
	h := schemaHandler(t, 300, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	helperCommand(h, 1200*time.Millisecond)
	cmd, _ := h.SchemaCommand("cli")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	waitFor(t, "the daemon to notice the run", 20*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		_, running := h.SchemaWaiting()
		return running
	})
	if !h.DB.WritesHeld() {
		t.Error("writes are not held for a run the daemon did not start")
	}
	v := h.schemaView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "running" || v.CanCancel || v.By != "cli" {
		t.Fatalf("view = %+v, want running, started by cli, with no cancel button", v)
	}
	if code, _ := postJSON(t, h.AdminSchemaUpdateCancel, "/unmask/admin/api/schema-update/cancel", user.RoleSuperadmin); code != http.StatusConflict {
		t.Errorf("cancel of someone else's run: %d, want 409", code)
	}
	if code, _ := postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin); code != http.StatusConflict {
		t.Errorf("run while one is going: %d, want 409", code)
	}
	waitFor(t, "the run to end", 15*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		_, running := h.SchemaWaiting()
		return !running && !h.DB.WritesHeld()
	})
	if !indexThere(t, h) || h.DB.EventJA4IndexHint() == "" {
		t.Error("index or hint missing after a run started elsewhere")
	}
}

// TestSchemaRunKilled: a run that dies without a word -- killed, out of
// memory -- leaves a record that says "running".  Its process is gone, so the
// daemon must not believe it: the writes are released and the notice offers
// the update again, saying the last attempt was interrupted.
func TestSchemaRunKilled(t *testing.T) {
	h := schemaHandler(t, 300, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	helperCommand(h, 30*time.Second)
	h.SchemaRefresh(context.Background())
	if code, body := postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("run: %d %v", code, body)
	}
	waitForRecord(t, h)
	h.schema.mu.Lock()
	child := h.schema.child
	h.schema.mu.Unlock()
	if child == nil {
		t.Fatal("no child process")
	}
	_ = child.Process.Kill()
	waitFor(t, "the daemon to see the run is gone", 10*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		_, running := h.SchemaWaiting()
		return !running && !h.DB.WritesHeld()
	})
	v := h.schemaView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "failed" || !v.CanRun || !strings.Contains(v.Err, "interrupted") {
		t.Fatalf("view after the run was killed = %+v, want failed (interrupted) and runnable again", v)
	}
	// The database is whole: the update can be run again, to the end.
	helperCommand(h, 0)
	if code, body := postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("run after the killed one: %d %v", code, body)
	}
	waitFor(t, "the second run to end", 15*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		n, running := h.SchemaWaiting()
		return n == 0 && !running
	})
	if !indexThere(t, h) {
		t.Fatal("index not built by the run after the killed one")
	}
}

// pagesWithTheHeader are admin pages, each rendered by its own template.  The
// notice is part of the header they all include; none of them lists it.
func pagesWithTheHeader(h *Handler) map[string]http.HandlerFunc {
	if h.BanMgr == nil {
		h.BanMgr = ban.New(h.DB, "", time.Hour) // the bans page lists from it
	}
	return map[string]http.HandlerFunc{
		"/unmask/admin/":          h.AdminTopOverview,
		"/unmask/admin/hunt/":     h.AdminHuntIndex,
		"/unmask/admin/stats/":    h.AdminStats,
		"/unmask/admin/bans/":     h.AdminBansIndex,
		"/unmask/admin/settings/": h.AdminSettingsIndex,
		"/unmask/admin/audit/":    h.AdminAuditIndex,
		"/unmask/admin/users/":    h.AdminUsersIndex,
	}
}

func renderAs(t *testing.T, fn http.HandlerFunc, path, role, lang string) string {
	t.Helper()
	req := asRole(httptest.NewRequest(http.MethodGet, path, nil), role)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: lang})
	rr := httptest.NewRecorder()
	fn(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s as %s: status %d", path, role, rr.Code)
	}
	body := rr.Body.String()
	// A template that fails part way still answers 200, with the page cut
	// short: the closing tag is what says it rendered to the end.
	if !strings.Contains(body, "</html>") {
		t.Fatalf("%s as %s: the page is cut short (no </html>): a template error", path, role)
	}
	return body
}

// TestSchemaNoticeOnEveryPage: the notice is where the operator is, whichever
// page that is, and says what waits in their language.  Nothing of it is on a
// page when nothing waits.
func TestSchemaNoticeOnEveryPage(t *testing.T) {
	h := schemaHandler(t, 200, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	h.SchemaRefresh(context.Background())

	for path, fn := range pagesWithTheHeader(h) {
		super := renderAs(t, fn, path, user.RoleSuperadmin, "en")
		if !strings.Contains(super, `id="schup"`) || !strings.Contains(super, `data-state="pending"`) {
			t.Errorf("%s: the notice is missing", path)
			continue
		}
		if !strings.Contains(super, "A database update is waiting") || !strings.Contains(super, `id="schup-run"`) {
			t.Errorf("%s: superadmin: no message or no run button", path)
		}
		if strings.Contains(super, "schema_update.") {
			t.Errorf("%s: a raw translation key is on the page", path)
		}
		if !strings.Contains(super, `data-api="/unmask/admin/api/schema-update"`) {
			t.Errorf("%s: the notice does not know where its API is", path)
		}
	}

	viewer := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleViewer, "en")
	if !strings.Contains(viewer, "A database update is waiting") {
		t.Error("viewer: the notice is for everyone who signs in")
	}
	if strings.Contains(viewer, `id="schup-run"`) {
		t.Error("viewer: the run button is the superadmin's")
	}
	if !strings.Contains(viewer, "A superadmin can run it.") {
		t.Error("viewer: the notice must say who can act on it")
	}

	ja := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "ja")
	if !strings.Contains(ja, "データベースの更新があります") || !strings.Contains(ja, "今すぐ実行") {
		t.Error("ja: the notice is not in Japanese")
	}

	// Applied: the notice of something waiting is gone from every page.
	if _, err := db.ApplySchemaUpdate(context.Background(), h.DB, db.SchemaUpdateOptions{Host: h.HostID, By: "cli"}); err != nil {
		t.Fatal(err)
	}
	h.SchemaRefresh(context.Background())
	for path, fn := range pagesWithTheHeader(h) {
		if body := renderAs(t, fn, path, user.RoleSuperadmin, "en"); strings.Contains(body, `data-state="pending"`) || strings.Contains(body, `id="schup-run"`) {
			t.Errorf("%s: still offers the update after it was applied", path)
		}
	}
}

// TestNoNoticeOnAnOrdinaryInstall: an install with nothing waiting renders
// none of the notice -- not its markup, not its script.
func TestNoNoticeOnAnOrdinaryInstall(t *testing.T) {
	h := installedHandler(t)
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	h.SchemaRefresh(context.Background())
	for path, fn := range pagesWithTheHeader(h) {
		if body := renderAs(t, fn, path, user.RoleSuperadmin, "en"); strings.Contains(body, "schup") {
			t.Errorf("%s: carries the schema update notice with nothing waiting", path)
		}
	}
}

// TestChangesWaitWhileWritesAreHeld: a schema update holds the write lock.
// A change made in the admin UI would wait out the busy timeout and fail with
// a driver error; it is answered at once instead, with what is going on --
// JSON for the API, a page for a form.  Reading is not affected, and the
// request that stops the update goes through.
func TestChangesWaitWhileWritesAreHeld(t *testing.T) {
	h := installedHandler(t)
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	reached := 0
	next := func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(http.StatusNoContent) }

	do := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "127.0.0.1:5555"
		r.AddCookie(issueSessionCookie(h.cfg().Secret.BVSecret, 1, "superadmin", false, false))
		r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok"})
		r.Header.Set("X-CSRF-Token", "tok")
		r.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
		rr := httptest.NewRecorder()
		h.AuthMiddleware(next)(rr, r)
		return rr
	}

	// Not held: everything goes through.
	if rr := do(http.MethodPost, "/unmask/admin/settings/save"); rr.Code != http.StatusNoContent {
		t.Fatalf("writes not held: POST answered %d", rr.Code)
	}

	h.DB.HoldWrites(true)
	defer h.DB.HoldWrites(false)
	reached = 0

	rr := do(http.MethodPost, "/unmask/admin/settings/save")
	if rr.Code != http.StatusServiceUnavailable || reached != 0 {
		t.Fatalf("a form post while writes are held: %d (handler reached %d times), want 503 and the handler untouched", rr.Code, reached)
	}
	if !strings.Contains(rr.Body.String(), "The database is being updated") || !strings.Contains(rr.Body.String(), `href="/unmask/admin/"`) {
		t.Errorf("the page does not say what is going on or offer a way back: %s", rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}

	rr = do(http.MethodPost, "/unmask/admin/api/notify/test")
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("an API post while writes are held: %d %s", rr.Code, rr.Header().Get("Content-Type"))
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body["error"] != "schema_update_running" || body["message"] == "" {
		t.Errorf("API body = %s", rr.Body.String())
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/unmask/admin/"},
		{http.MethodGet, "/unmask/admin/api/schema-update"},
		{http.MethodPost, "/unmask/admin/api/schema-update/cancel"},
		{http.MethodPost, "/unmask/admin/logout"},
	} {
		reached = 0
		if rr := do(c.method, c.path); rr.Code != http.StatusNoContent || reached != 1 {
			t.Errorf("%s %s while writes are held: %d (handler reached %d times), want it to go through", c.method, c.path, rr.Code, reached)
		}
	}
}

// TestChallengeServesWhileTheWriteLockIsHeld: the promise the notice makes.
// A schema update holds SQLite's write lock for as long as the index build
// takes; the visitor's side of the daemon -- the challenge page, its beacons,
// the verification that issues the cookie, the forward-auth check -- has to
// go on answering at its usual speed.  One write on any of those paths would
// wait out the busy timeout, five seconds a request, and then fail.
//
// The lock here is a real one, taken on another connection the way the
// update's process takes it.
func TestChallengeServesWhileTheWriteLockIsHeld(t *testing.T) {
	h := installedHandler(t)
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	s.Secret.CaptchaSecretBase = "test-base"
	s.Challenge.Default.PowCookieValidSeconds = 86400 * 7
	s.Challenge.Default.DebugRateLimitPer5Min = 100
	s.Challenge.Default.CaptchaProvider.Provider = "builtin"
	s.Challenge.Default.CaptchaProvider.BuiltinScoreThreshold = 0.5
	h.SetSettings(s)
	h.BanMgr = ban.New(h.DB, filepath.Join(t.TempDir(), "ban.list"), time.Hour)
	fl := events.StartFlusher(h.DB, 10, 50)
	t.Cleanup(func() { events.StopFlusher(); _ = fl })

	ctx := context.Background()
	lock, err := h.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_, _ = lock.ExecContext(ctx, "ROLLBACK")
			_ = lock.Close()
		}
	}
	defer release()
	h.DB.HoldWrites(true)
	defer h.DB.HoldWrites(false)

	const ip = "198.51.100.7"
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
	within := func(name string, limit time.Duration, fn func() int) int {
		t.Helper()
		t0 := time.Now()
		code := fn()
		if took := time.Since(t0); took > limit {
			t.Errorf("%s took %v with the write lock held (limit %v): something on this path waits for the lock", name, took, limit)
		}
		return code
	}
	req := func(method, path, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-Real-IP", ip)
		r.Header.Set("User-Agent", ua)
		r.Header.Set("X-Client-JA4", "t13d1517h2_aaa_bbb")
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		return r
	}

	// The challenge page.
	var page string
	code := within("the challenge page", time.Second, func() int {
		rr := httptest.NewRecorder()
		h.ServeChallengeOrJSON(rr, req(http.MethodGet, "/unmask/challenge/?u=%2F", ""))
		page = rr.Body.String()
		return rr.Code
	})
	if code != http.StatusOK && code != http.StatusForbidden {
		t.Fatalf("the challenge page answered %d", code)
	}
	if !strings.Contains(page, "<html") {
		t.Fatalf("the challenge page is not a page: %.200s", page)
	}

	// Its beacons.
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase, ip)
	for _, phase := range []string{"load", "pow_pass"} {
		if code := within("the "+phase+" beacon", time.Second, func() int {
			rr := httptest.NewRecorder()
			h.DebugBeacon(rr, req(http.MethodPost, "/unmask/api/debug", `{"phase":"`+phase+`","flags":3,"reload_count":0,"ua":"x","bt":"`+bt+`"}`))
			return rr.Code
		}); code != http.StatusOK {
			t.Errorf("the %s beacon answered %d", phase, code)
		}
	}

	// The verification that issues the cookie.
	ct := captcha.IssueToken("test-base", ip)
	var cookie string
	if code := within("the verification", time.Second, func() int {
		rr := httptest.NewRecorder()
		h.VerifyJSON(rr, req(http.MethodPost, "/unmask/api/verify",
			`{"token":"x","ct":"`+ct+`","sig":{"hasMouseEvents":true,"clickAt":3000,"mouseTrail":[[10,10,1],[40,33,80],[70,55,160],[100,77,240],[130,99,320]],"windowSize":[1280,800]}}`))
		for _, c := range rr.Result().Cookies() {
			if c.Name == "_bv" {
				cookie = c.Value
			}
		}
		return rr.Code
	}); code != http.StatusOK {
		t.Errorf("the verification answered %d", code)
	}
	if cookie == "" {
		t.Error("no _bv cookie: a visitor who passes during the update would be challenged again")
	}

	// The forward-auth check, without and with the cookie just issued.
	for _, c := range []struct{ name, cookie string }{{"the forward-auth check", ""}, {"the forward-auth check with a cookie", cookie}} {
		within(c.name, time.Second, func() int {
			r := req(http.MethodGet, "/unmask/api/check", "")
			r.RemoteAddr = "127.0.0.1:5555"
			r.Header.Set("X-Original-URI", "/")
			r.Header.Set("X-Forwarded-Host", "example.com")
			if c.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "_bv", Value: c.cookie})
			}
			rr := httptest.NewRecorder()
			h.AuthCheck(rr, r)
			return rr.Code
		})
	}

	// An automatic ban (a honeypot hit) is kept, not thrown at the lock.
	within("an automatic ban", 200*time.Millisecond, func() int {
		h.BanMgr.AddWithSourceAction(ctx, "203.0.113.50", "", ban.SourceHoneypot, "trap", "", "deny")
		return 0
	})

	// Nothing of the above reached the table while the lock was held ...
	var n int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil {
		t.Fatalf("reading during the hold: %v", err)
	}
	if n != 0 {
		t.Errorf("%d events were written against the held lock", n)
	}
	// ... and all of it does once the lock is free.
	release()
	h.DB.HoldWrites(false)
	waitFor(t, "the events recorded during the hold", 10*time.Second, func() bool {
		var n int
		_ = h.DB.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&n)
		return n >= 3
	})
}

// TestSchemaNoticeWhileRunning: what the page carries while the update runs --
// the state, the place the elapsed time is written into, and the cancel button
// for the one who may press it.
func TestSchemaNoticeWhileRunning(t *testing.T) {
	h := schemaHandler(t, 300, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	helperCommand(h, 30*time.Second)
	h.SchemaRefresh(context.Background())
	if code, body := postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("run: %d %v", code, body)
	}
	defer func() { _ = h.schemaCancel() }()
	waitForRecord(t, h)

	super := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "en")
	for _, want := range []string{`data-state="running"`, `id="schup-elapsed"`, `id="schup-cancel"`, "Updating the database.", "The challenge is working."} {
		if !strings.Contains(super, want) {
			t.Errorf("superadmin, running: the page lacks %q", want)
		}
	}
	if strings.Contains(super, `id="schup-run"`) {
		t.Error("the run button is on the page while the update runs")
	}
	viewer := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleViewer, "ja")
	if !strings.Contains(viewer, `data-state="running"`) || !strings.Contains(viewer, "データベースを更新しています") {
		t.Error("viewer, running: the notice is missing")
	}
	if strings.Contains(viewer, `id="schup-cancel"`) {
		t.Error("viewer: the cancel button is the superadmin's")
	}

	// The status the page polls.
	req := asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/api/schema-update", nil), user.RoleViewer)
	rr := httptest.NewRecorder()
	h.AdminSchemaUpdateStatus(rr, req)
	var v SchemaUpdateView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil || v.State != "running" || v.StartedAt == 0 || v.Now == 0 {
		t.Errorf("status while running = %s (%v)", rr.Body.String(), err)
	}

	if code, body := postJSON(t, h.AdminSchemaUpdateCancel, "/unmask/admin/api/schema-update/cancel", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("cancel: %d %v", code, body)
	}
	waitFor(t, "the run to stop", 20*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		_, running := h.SchemaWaiting()
		return !running
	})
	after := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "en")
	if !strings.Contains(after, `data-state="pending"`) || !strings.Contains(after, "The last update was cancelled.") || !strings.Contains(after, `id="schup-run"`) {
		t.Error("after a cancel the page must offer the update again and say the last one was cancelled")
	}
	// With nothing to show the status says so, and nothing else.
	if _, err := db.ApplySchemaUpdate(context.Background(), h.DB, db.SchemaUpdateOptions{Host: h.HostID, By: "cli"}); err != nil {
		t.Fatal(err)
	}
	h.SchemaRefresh(context.Background())
	if _, err := h.DB.Exec(`DELETE FROM unmask_maint_state WHERE name = 'schema_update'`); err != nil {
		t.Fatal(err)
	}
	h.SchemaRefresh(context.Background())
	rr = httptest.NewRecorder()
	h.AdminSchemaUpdateStatus(rr, asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/api/schema-update", nil), user.RoleViewer))
	var none map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &none); err != nil || none["state"] != "none" {
		t.Errorf("status with nothing to show = %s", rr.Body.String())
	}
}

// TestSchemaNoticeWordsFollowTheDatabase: the notice says what waits only
// where something does.  On SQLite the run holds the write lock, so the page
// warns that saving settings has to wait; MariaDB builds the index online, and
// the same warning there would be untrue -- it would have an operator plan a
// maintenance window for an update that stops nothing.
func TestSchemaNoticeWordsFollowTheDatabase(t *testing.T) {
	h := schemaHandler(t, 200, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	h.SchemaRefresh(context.Background())
	v := h.schemaView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "pending" {
		t.Fatalf("view = %+v, want the update pending", v)
	}
	if !v.HoldsWrites {
		t.Fatal("SQLite: the run holds the write lock, and the view must say so")
	}
	onSQLite := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "en")
	if !strings.Contains(onSQLite, "saving settings wait until it has finished") {
		t.Error("SQLite: the notice must say that changes wait")
	}
	if !strings.Contains(onSQLite, "not possible while it runs") {
		t.Error("SQLite: the confirmation must say that changes are not possible during the run")
	}

	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	render := func(v SchemaUpdateView, lang i18n.Lang) string {
		t.Helper()
		var b strings.Builder
		if err := tmpl.ExecuteTemplate(&b, "schema_update_notice", map[string]any{
			"SchemaUpdate": &v, "Lang": lang, "BasePath": "/unmask",
		}); err != nil {
			t.Fatalf("render the notice: %v", err)
		}
		return b.String()
	}
	for _, c := range []struct {
		lang   i18n.Lang
		state  string
		want   []string
		absent []string
	}{
		{i18n.LangEN, "pending",
			[]string{"A database update is waiting", "and so do changes such as saving settings", `data-l-confirm="Start the database update?"`},
			[]string{"wait until", "recorded afterwards", "not possible while it runs"}},
		{i18n.LangEN, "running",
			[]string{"Updating the database", "go through as usual"},
			[]string{"wait until"}},
		{i18n.LangJA, "pending",
			[]string{"データベースの更新があります", "そのまま行えます", `data-l-confirm="データベースの更新を始めます。よろしいですか?"`},
			[]string{"完了するまで", "完了後に記録", "変更ができません"}},
		{i18n.LangJA, "running",
			[]string{"データベースを更新しています", "そのまま行えます"},
			[]string{"完了するまで"}},
	} {
		online := *v
		online.HoldsWrites = false
		online.State = c.state
		if c.state == "running" {
			online.CanRun, online.StartedAt = false, online.Now-5
		}
		online.Est = estimateText(c.lang, 20*time.Second, 40*time.Second)
		out := render(online, c.lang)
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("online, %s, %s: the notice lacks %q", c.lang, c.state, w)
			}
		}
		for _, a := range c.absent {
			if strings.Contains(out, a) {
				t.Errorf("online, %s, %s: the notice says %q, which is not so on a database that builds online", c.lang, c.state, a)
			}
		}
		if strings.Contains(out, "schema_update.") {
			t.Errorf("online, %s, %s: a raw translation key is in the notice", c.lang, c.state)
		}
	}
}

// TestQuickRunFromTheButtonIsAnswered: an update started with the button is
// answered with "finished" however quick it was.  A run under a second used to
// be no news at all -- right for a new install's first migrate from a shell,
// wrong for the administrator who pressed the button and saw the notice
// vanish with nothing in its place (a fast machine builds a small table's
// index in less than that).
func TestQuickRunFromTheButtonIsAnswered(t *testing.T) {
	h := schemaHandler(t, 50, 0)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	quick := func(by string) db.SchemaUpdateRecord {
		now := time.Now().Unix()
		return db.SchemaUpdateRecord{
			State: db.SchemaUpdateDone, Items: []string{"0032_event_ja4_index"}, Host: h.HostID, By: by,
			StartedAt: now, EndedAt: now, Seconds: 0.3,
		}
	}
	ctx := context.Background()

	if err := h.DB.SaveMaintState(ctx, db.MaintSchemaUpdate, quick("alice")); err != nil {
		t.Fatal(err)
	}
	h.SchemaRefresh(ctx)
	v := h.schemaView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "done" {
		t.Fatalf("view = %+v, want the finished notice for a run started with the button", v)
	}
	if v.Took != "under 1 s" {
		t.Errorf("took = %q, want it worded (not \"0 s\")", v.Took)
	}
	if ja := h.schemaView(user.RoleSuperadmin, i18n.LangJA); ja == nil || ja.Took != "1 秒未満" {
		t.Errorf("ja view = %+v", ja)
	}
	body := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "en")
	if !strings.Contains(body, "The database update finished (under 1 s).") || !strings.Contains(body, `id="schup-dismiss"`) {
		t.Error("the page does not say that the update finished")
	}

	// From a shell, a run that took no time is a new install's first migrate.
	if err := h.DB.SaveMaintState(ctx, db.MaintSchemaUpdate, quick(db.SchemaUpdateByCLI)); err != nil {
		t.Fatal(err)
	}
	h.SchemaRefresh(ctx)
	if v := h.schemaView(user.RoleSuperadmin, i18n.LangEN); v != nil {
		t.Errorf("view = %+v, want nothing for a quick run from a shell", v)
	}
}
