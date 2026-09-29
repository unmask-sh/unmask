package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// holdTheWriteLock takes SQLite's write lock the way a schema update's index
// build does, and holds the daemon's writers as the daemon does when it sees
// one.  The returned function lets both go.
func holdTheWriteLock(t *testing.T, h *Handler) (release func()) {
	t.Helper()
	ctx := context.Background()
	lock, err := h.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	h.DB.HoldWrites(true)
	var once sync.Once
	release = func() {
		once.Do(func() {
			h.DB.HoldWrites(false)
			_, _ = lock.ExecContext(ctx, "ROLLBACK")
			_ = lock.Close()
		})
	}
	t.Cleanup(release)
	return release
}

// TestSignInDuringAHold: signing in writes the last-login time and an audit
// row.  Under a schema update's lock each used to wait out the busy timeout
// -- ten seconds to sign in, and the audit row lost -- which is when an
// operator signs in to watch the update, or to answer an attack.  They wait
// in memory now, and are written when the lock is free.
func TestSignInDuringAHold(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	ctx := context.Background()
	if _, err := h.UserRepo.CreateWithProfile(ctx, "gina", "test-password-gina", "superadmin", "", false); err != nil {
		t.Fatal(err)
	}
	release := holdTheWriteLock(t, h)
	form := url.Values{"username": {"gina"}, "password": {"test-password-gina"}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	t0 := time.Now()
	h.AdminLoginPost(rr, req)
	if took := time.Since(t0); took > 2*time.Second {
		t.Errorf("signing in took %v under the lock", took)
	}
	signedIn := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			signedIn = true
		}
	}
	if !signedIn {
		t.Fatalf("no session under the lock (code %d)", rr.Code)
	}
	logins := func() int {
		var n int
		if err := h.DB.QueryRow(`SELECT COUNT(*) FROM unmask_user_audit WHERE action = 'login' AND username = 'gina'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := logins(); n != 0 {
		t.Fatalf("%d audit rows written under the lock", n)
	}
	release()
	h.UserRepo.FlushHeld(ctx)
	if n := logins(); n != 1 {
		t.Errorf("after the lock: %d login rows, want the one kept", n)
	}
	var last *time.Time
	if err := h.DB.QueryRow(`SELECT last_login FROM unmask_user WHERE username = 'gina'`).Scan(&last); err != nil || last == nil {
		t.Errorf("last_login not written after the lock (%v)", err)
	}
}

// TestBeaconLimitDuringAHold: the beacon's per-address limit counts the rows
// written, and under a hold nothing is written until the lock is free.  The
// beacons accepted meanwhile are counted in memory: one token no longer sends
// without limit, pushing visitors' own events out of the kept list.
func TestBeaconLimitDuringAHold(t *testing.T) {
	h := installedHandler(t)
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	s.Secret.CaptchaSecretBase = "test-base"
	s.Challenge.Default.DebugRateLimitPer5Min = 20
	h.SetSettings(s)
	// The daemon's flusher, which keeps what a hold does not let it write.
	events.StartFlusher(h.DB, 10, 50)
	t.Cleanup(events.StopFlusher)
	holdTheWriteLock(t, h)

	const ip = "198.51.100.9"
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase, ip)
	accepted, refused := 0, 0
	t0 := time.Now()
	for i := 0; i < 40; i++ {
		r := httptest.NewRequest(http.MethodPost, "/unmask/api/debug", strings.NewReader(`{"phase":"load","flags":0,"reload_count":0,"ua":"x","bt":"`+bt+`"}`))
		r.Header.Set("X-Real-IP", ip)
		r.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.DebugBeacon(rr, r)
		switch rr.Code {
		case http.StatusOK:
			accepted++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Fatalf("beacon %d answered %d: %s", i, rr.Code, rr.Body.String())
		}
	}
	if took := time.Since(t0); took > 2*time.Second {
		t.Errorf("40 beacons took %v under the lock", took)
	}
	if accepted != 20 || refused != 20 {
		t.Errorf("under the hold: %d accepted, %d refused; want the limit of 20 to hold", accepted, refused)
	}
}

// TestFailedStartIsShown: a run started with the button that ends before it
// can keep a record -- it cannot open the database, it finds another run --
// is answered with its own last words.  The notice used to return to
// "waiting" as if the button had never been pressed.
func TestFailedStartIsShown(t *testing.T) {
	h := schemaHandler(t, 200, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	h.SchemaCommand = func(by string) (*exec.Cmd, error) {
		cmd := exec.Command("sh", "-c", `echo "migrate: open /var/lib/unmask/unmask.sqlite: permission denied" >&2; exit 1`)
		out := &logLines{prefix: "schema update: "}
		cmd.Stdout, cmd.Stderr = out, out
		return cmd, nil
	}
	h.SchemaRefresh(context.Background())
	if code, body := postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("run: %d %v", code, body)
	}
	waitFor(t, "the run to be reaped", 10*time.Second, func() bool {
		h.schema.mu.Lock()
		defer h.schema.mu.Unlock()
		return h.schema.child == nil && h.schema.childPID == 0
	})
	v := h.schemaView(user.RoleSuperadmin, i18n.LangEN)
	if v == nil || v.State != "failed" || !strings.Contains(v.Err, "permission denied") || !v.CanRun {
		t.Fatalf("view after a start that failed = %+v, want failed with the run's own words, and a retry", v)
	}
	if strings.HasPrefix(v.Err, "migrate: ") {
		t.Errorf("the reason keeps its prefix: %q", v.Err)
	}
	// A run that then gets as far as its record replaces the message.
	helperCommand(h, 0)
	if code, body := postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin); code != http.StatusOK {
		t.Fatalf("retry: %d %v", code, body)
	}
	waitFor(t, "the retry to end", 15*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		n, running := h.SchemaWaiting()
		return n == 0 && !running
	})
	if v := h.schemaView(user.RoleSuperadmin, i18n.LangEN); v == nil || v.State != "done" {
		t.Errorf("after a retry that worked: %+v, want done", v)
	}
}

// TestDoublePressStartsOneRun: two presses of the button at once start one
// run, write one audit row, and tell the other that a run is going.
func TestDoublePressStartsOneRun(t *testing.T) {
	h := schemaHandler(t, 200, 0.001)
	if _, err := db.MigrateWith(h.DB, db.MigrateOptions{Defer: true, DeferOver: h.cfg().DB.SchemaUpdateDeferOver()}); err != nil {
		t.Fatal(err)
	}
	helperCommand(h, 2*time.Second)
	h.SchemaRefresh(context.Background())
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _ = postJSON(t, h.AdminSchemaUpdateRun, "/unmask/admin/api/schema-update/run", user.RoleSuperadmin)
		}(i)
	}
	wg.Wait()
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("two presses: %v, want one 200 and one 409", codes)
	}
	waitFor(t, "the run to end", 20*time.Second, func() bool {
		h.SchemaRefresh(context.Background())
		n, running := h.SchemaWaiting()
		return n == 0 && !running
	})
	var n int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM unmask_user_audit WHERE action = 'schema_update.run'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d audit rows for one run", n)
	}
}

// TestSettingsDoNotCallTheDatabaseUnwritableDuringAnUpdate: the retention
// tab probes whether the daemon can write.  Under a schema update's lock the
// probe waited out the busy timeout and then called the database unwritable,
// with a chown and a restart as the fix -- a restart that stops the update.
func TestSettingsDoNotCallTheDatabaseUnwritableDuringAnUpdate(t *testing.T) {
	h := schemaHandler(t, 50, 0)
	holdTheWriteLock(t, h)
	req := asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/retention/", nil), user.RoleSuperadmin)
	req.SetPathValue("tab", "retention")
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	t0 := time.Now()
	h.AdminSettingsIndex(rr, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(body, "</html>") {
		t.Fatalf("the retention tab: %d, cut short = %v", rr.Code, !strings.Contains(body, "</html>"))
	}
	if took := time.Since(t0); took > 3*time.Second {
		t.Errorf("the retention tab took %v under the lock", took)
	}
	if strings.Contains(body, "NOT writable") || strings.Contains(body, "systemctl restart unmask") {
		t.Error("the tab calls the database unwritable during an update, and offers a restart")
	}
	if !strings.Contains(body, "A database update is running") {
		t.Error("the tab does not say why the write was not probed")
	}
}

// TestPasswordResetDuringAHold: a reset writes the new password and spends
// the token.  Under a hold it failed, and said "invalid token" of a token that
// was still good; it says what is going on now.
func TestPasswordResetDuringAHold(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	holdTheWriteLock(t, h)
	form := url.Values{"token": {"abc"}, "password": {"x-long-enough-1"}, "password2": {"x-long-enough-1"}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	t0 := time.Now()
	h.AdminResetPasswordPost(rr, req)
	if took := time.Since(t0); took > 2*time.Second {
		t.Errorf("the reset took %v under the lock", took)
	}
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "The database is being updated") {
		t.Errorf("a reset under the hold: %d %.200s", rr.Code, rr.Body.String())
	}
}

// TestStopSchemaRunCancelsTheChild: the daemon's shutdown stops the run it
// started and waits for it: the run records itself as cancelled, and the lock
// the last writes need is free.  Left running, it lost its output pipe and
// died on its next line without saying how it ended.
func TestStopSchemaRunCancelsTheChild(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t0 := time.Now()
	h.StopSchemaRun(ctx)
	if took := time.Since(t0); took > 10*time.Second {
		t.Errorf("stopping the run took %v", took)
	}
	h.schema.mu.Lock()
	gone := h.schema.child == nil
	h.schema.mu.Unlock()
	if !gone {
		t.Fatal("the run is still going after StopSchemaRun")
	}
	rec, ok, err := h.DB.LoadSchemaUpdate(context.Background())
	if err != nil || !ok || rec.State != db.SchemaUpdateCancelled {
		t.Errorf("record after the stop = %+v (%v, %v), want cancelled", rec, ok, err)
	}
	if held, _ := h.DB.SchemaRunLockHeld(context.Background()); held {
		t.Error("the run's lock is still held after it stopped")
	}
	// Nothing to stop: returns at once.
	t0 = time.Now()
	h.StopSchemaRun(ctx)
	if time.Since(t0) > time.Second {
		t.Error("StopSchemaRun with no run waited")
	}
}
