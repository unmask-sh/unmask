package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// tokenPaths points both setup-token paths into dir for the test and
// returns them.
func tokenPaths(t *testing.T, dir string) (current, legacy string) {
	t.Helper()
	oldTok, oldLegacy := SetupTokenPath, legacySetupTokenPath
	SetupTokenPath = filepath.Join(dir, ".setup-token")
	legacySetupTokenPath = filepath.Join(dir, "legacy", ".setup-token")
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = oldTok, oldLegacy })
	return SetupTokenPath, legacySetupTokenPath
}

// SetupCompleted is what a start that cannot open its database decides by:
// an install whose wizard can still be entered, or whose config names no
// database, is not set up and keeps the behaviour it always had; anything
// else is a set-up install whose database is away.
func TestSetupCompleted(t *testing.T) {
	sqliteDB := settings.DB{Driver: "sqlite", SQLitePath: "/var/lib/unmask/unmask.sqlite"}
	mariaDB := settings.DB{Driver: "mariadb", MariaDB: settings.MariaDB{Host: "db.internal", Port: 3306, User: "unmask", Database: "unmask"}}
	const cfgPath = "/etc/unmask/config.yml"

	cases := []struct {
		name   string
		token  string // "", "current", "legacy", "empty" (a token file with nothing in it)
		open   bool   // UNMASK_OPEN_SETUP=1
		config string
		db     settings.DB
		want   bool
	}{
		{name: "sqlite, wizard sealed", config: cfgPath, db: sqliteDB, want: true},
		{name: "mariadb, wizard sealed", config: cfgPath, db: mariaDB, want: true},
		{name: "driver left to the default", config: cfgPath, db: settings.DB{SQLitePath: "/data/u.sqlite"}, want: true},
		{name: "setup token on disk", token: "current", config: cfgPath, db: mariaDB, want: false},
		{name: "setup token at the pre-0.1.9 path", token: "legacy", config: cfgPath, db: mariaDB, want: false},
		{name: "an empty token file is still a wizard that has not finished", token: "empty", config: cfgPath, db: mariaDB, want: false},
		{name: "wizard opened by the environment", open: true, config: cfgPath, db: mariaDB, want: false},
		{name: "no config file", config: "", db: sqliteDB, want: false},
		{name: "mariadb without a database name", config: cfgPath, db: settings.DB{Driver: "mariadb", MariaDB: settings.MariaDB{Host: "db.internal", Port: 3306, User: "unmask"}}, want: false},
		{name: "mariadb without a host", config: cfgPath, db: settings.DB{Driver: "mariadb", MariaDB: settings.MariaDB{Port: 3306, User: "unmask", Database: "unmask"}}, want: false},
		{name: "sqlite without a path", config: cfgPath, db: settings.DB{Driver: "sqlite"}, want: false},
		{name: "a driver the daemon does not know", config: cfgPath, db: settings.DB{Driver: "postgres", SQLitePath: "/data/u.sqlite"}, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			current, legacy := tokenPaths(t, dir)
			switch c.token {
			case "current":
				mustWrite(t, current, "f00dfacecafe\n")
			case "legacy":
				mustWrite(t, legacy, "f00dfacecafe\n")
			case "empty":
				mustWrite(t, current, "")
			}
			t.Setenv("UNMASK_OPEN_SETUP", "")
			if c.open {
				t.Setenv("UNMASK_OPEN_SETUP", "1")
			}
			if got := SetupCompleted(c.config, c.db); got != c.want {
				t.Errorf("SetupCompleted = %v, want %v", got, c.want)
			}
		})
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The start clears a stale token (an admin exists) without waiting for the
// first admin request, so that the token's absence means "set up" at the
// next start, whether or not anyone opened the admin in between.
func TestClearStaleSetupToken(t *testing.T) {
	dir := t.TempDir()
	current, legacy := tokenPaths(t, dir)
	mustWrite(t, current, "f00dfacecafe\n")
	mustWrite(t, legacy, "0ldt0ken\n")
	if !setupTokenOnDisk() {
		t.Fatal("precondition: a token on disk")
	}
	ClearStaleSetupToken()
	for _, p := range []string{current, legacy} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s is still there (%v)", p, err)
		}
	}
	ClearStaleSetupToken() // nothing to clear: no error, no file
	if setupTokenOnDisk() {
		t.Error("a token appeared")
	}
}

// waitingHandler is a daemon on a set-up install that started without its
// database: no handle, no repositories, the settings it loaded.
func waitingHandler(t *testing.T) *Handler {
	t.Helper()
	tokenPaths(t, t.TempDir())
	h := &Handler{DBWaiting: true, ConfigPath: filepath.Join(t.TempDir(), "config.yml")}
	h.SetSettings(settings.Settings{
		Server: settings.Server{BasePath: "/unmask"},
		Secret: settings.Secret{BVSecret: "test-secret", AdminSecret: reconfAdminSecret},
	})
	return h
}

// Every admin route of a daemon that waits for its database answers 503 and
// says what is going on, in the operator's language -- where it used to
// redirect to a setup wizard that sealed itself when the install was set up.
func TestDBWaitingAdminAnswers503(t *testing.T) {
	h := waitingHandler(t)
	passed := 0
	next := func(http.ResponseWriter, *http.Request) { passed++ }

	if needed, step := h.SetupNeeded(httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)); needed {
		t.Errorf("SetupNeeded reports %q on a set-up install whose database is away", step)
	}

	get := func(mw http.HandlerFunc, method, path, lang string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "192.0.2.10:5555"
		if lang != "" {
			r.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: lang})
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		mw(rr, r)
		return rr
	}
	auth, gate := h.AuthMiddleware(next), h.AdminIPAllowMiddleware(h.SetupGate(next))

	for _, c := range []struct {
		name string
		mw   http.HandlerFunc
		path string
	}{
		{"a page behind the session", auth, "/unmask/admin/"},
		{"the sign-in page", gate, "/unmask/admin/login"},
		{"the wizard, with nobody signed in", h.SetupGate(next), "/unmask/admin/setup/"},
	} {
		rr := get(c.mw, http.MethodGet, c.path, "en")
		body := rr.Body.String()
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d, want 503", c.name, rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "" {
			t.Errorf("%s: redirected to %q", c.name, loc)
		}
		if rr.Header().Get("Retry-After") == "" {
			t.Errorf("%s: no Retry-After", c.name)
		}
		if !strings.Contains(body, i18n.T(i18n.LangEN, "dbwait.title")) || !strings.Contains(body, "keeps retrying") {
			t.Errorf("%s: the page does not say the database is away and being retried:\n%s", c.name, body)
		}
		if !strings.Contains(body, `http-equiv="refresh"`) {
			t.Errorf("%s: a read does not reload itself", c.name)
		}
		if strings.Contains(body, "/admin/setup/") {
			t.Errorf("%s: the page points a visitor with no session at the wizard", c.name)
		}
	}
	if passed != 0 {
		t.Fatalf("%d request(s) reached a handler that has no database", passed)
	}

	// In Japanese for an operator who reads the admin in Japanese.
	if body := get(auth, http.MethodGet, "/unmask/admin/hunt/", "ja").Body.String(); !strings.Contains(body, i18n.T(i18n.LangJA, "dbwait.title")) {
		t.Errorf("the Japanese page lacks its title:\n%s", body)
	}

	// A JSON route answers in JSON: the page's fetch reads an error.
	rr := get(auth, http.MethodGet, "/unmask/admin/api/funnel", "")
	var js map[string]any
	if rr.Code != http.StatusServiceUnavailable || json.Unmarshal(rr.Body.Bytes(), &js) != nil || js["error"] != "database unavailable" {
		t.Errorf("JSON route: %d %q", rr.Code, rr.Body.String())
	}

	// A write is not asked again by the page: reloading a POST is another request.
	rr = get(auth, http.MethodPost, "/unmask/admin/settings/save", "en")
	if rr.Code != http.StatusServiceUnavailable || strings.Contains(rr.Body.String(), `http-equiv="refresh"`) {
		t.Errorf("POST: %d, reload in the page = %v", rr.Code, strings.Contains(rr.Body.String(), `http-equiv="refresh"`))
	}
}

// The allowlists still stand in front: an address they turn away is told
// "Forbidden" and nothing about the daemon's state.
func TestDBWaitingKeepsTheAdminAllowlist(t *testing.T) {
	h := waitingHandler(t)
	s := h.snapshotSettings()
	s.Nginx.AdminAllowedIPs = []string{"198.51.100.0/24"}
	h.SetSettings(s)
	next := func(http.ResponseWriter, *http.Request) { t.Error("reached a handler") }
	for name, mw := range map[string]http.HandlerFunc{
		"session route": h.AuthMiddleware(next),
		"sign-in":       h.AdminIPAllowMiddleware(h.SetupGate(next)),
	} {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil)
		r.RemoteAddr = "203.0.113.9:5555"
		rr := httptest.NewRecorder()
		mw(rr, r)
		if rr.Code != http.StatusForbidden || strings.Contains(rr.Body.String(), "atabase") {
			t.Errorf("%s from outside the allowlist: %d %q, want a bare 403", name, rr.Code, rr.Body.String())
		}
	}
}

// A signed-in superadmin keeps the one door that was open before: the wizard
// in its reconfigure mode, where the daemon can be pointed at where the
// database went.  The 503 page shows them the way; nobody else gets either.
func TestDBWaitingLeavesTheWizardToASuperadmin(t *testing.T) {
	h := waitingHandler(t)
	passed := 0
	gate := h.SetupGate(func(http.ResponseWriter, *http.Request) { passed++ })

	req := func(path string, c *http.Cookie) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = "192.0.2.10:5555"
		r.AddCookie(c)
		return r
	}
	super := superadminCookie(1)
	viewer := issueSessionCookie(reconfAdminSecret, "/", 2, user.RoleViewer, false, false, 0)

	rr := httptest.NewRecorder()
	gate(rr, req("/unmask/admin/setup/", super))
	if passed != 1 {
		t.Fatalf("a superadmin's session did not reach the wizard: %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	gate(rr, req("/unmask/admin/setup/", viewer))
	if passed != 1 || rr.Code != http.StatusServiceUnavailable {
		t.Errorf("a viewer's session on the wizard: %d (reached: %d), want 503", rr.Code, passed)
	}

	// The page behind the session: 503 for both, the way to the wizard for
	// the superadmin alone.
	auth := h.AuthMiddleware(func(http.ResponseWriter, *http.Request) { t.Error("reached a page that needs the database") })
	for _, c := range []struct {
		name   string
		cookie *http.Cookie
		link   bool
	}{{"superadmin", super, true}, {"viewer", viewer, false}} {
		rr := httptest.NewRecorder()
		auth(rr, req("/unmask/admin/", c.cookie))
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d, want 503", c.name, rr.Code)
		}
		if got := strings.Contains(rr.Body.String(), `href="/unmask/admin/setup/"`); got != c.link {
			t.Errorf("%s: link to the wizard = %v, want %v", c.name, got, c.link)
		}
	}
}

// An install that was never set up is not waiting: its admin goes to the
// wizard, as it always did.
func TestNoDatabaseBeforeSetupStillGoesToTheWizard(t *testing.T) {
	h := waitingHandler(t)
	h.DBWaiting = false
	rr := httptest.NewRecorder()
	h.AuthMiddleware(func(http.ResponseWriter, *http.Request) { t.Error("reached a handler") })(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/unmask/admin/setup/" {
		t.Errorf("fresh install: %d -> %q, want a redirect to the wizard", rr.Code, rr.Header().Get("Location"))
	}
	if needed, step := h.SetupNeeded(httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)); !needed || step != "db" {
		t.Errorf("SetupNeeded = (%v, %q), want (true, db)", needed, step)
	}
}

// The door left open leads somewhere: a signed-in superadmin walks the
// wizard on a daemon that has no database at all -- the handlers it passes
// through were only ever run with one -- points it at a database that
// answers, and the daemon is scheduled to start over with it.
func TestDBWaitingSuperadminRepointsTheDatabase(t *testing.T) {
	dir := t.TempDir()
	tokenPaths(t, dir)
	// The configured database cannot be opened: its directory is a file.
	blocker := filepath.Join(dir, "gone")
	mustWrite(t, blocker, "")
	away := settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(blocker, "unmask.sqlite")}
	cfgPath := filepath.Join(dir, "config.yml")
	boot := settings.Settings{
		DB:     away,
		Server: settings.Server{BasePath: "/unmask"},
		Secret: settings.Secret{BVSecret: "test-secret", AdminSecret: reconfAdminSecret},
	}
	if err := settings.Save(boot, cfgPath); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DBWaiting: true, ConfigPath: cfgPath, Version: "0.9.9"}
	h.SetSettings(boot)

	reexecs := 0
	prev := scheduleReexecFn
	scheduleReexecFn = func() { reexecs++ }
	t.Cleanup(func() { scheduleReexecFn = prev })

	session := superadminCookie(1)
	t.Cleanup(func() { dropWizardState("sess:1") })
	csrf := csrfTokenFor(reconfAdminSecret, session.Value)
	do := func(fn http.HandlerFunc, method string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/unmask/admin/setup/", strings.NewReader(form.Encode()))
		r.RemoteAddr = "192.0.2.10:5555"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(session)
		w := httptest.NewRecorder()
		h.SetupGate(fn)(w, r)
		return w
	}
	step := func(fn http.HandlerFunc, form url.Values) string {
		t.Helper()
		w := do(fn, http.MethodPost, form)
		loc := w.Header().Get("Location")
		if w.Code != http.StatusFound || strings.Contains(loc, "err=") {
			t.Fatalf("wizard step: %d -> %q: %s", w.Code, loc, w.Body.String())
		}
		return loc
	}

	if w := do(h.AdminSetupIndex, http.MethodGet, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="sqlite_path"`) {
		t.Fatalf("the wizard's database step: %d", w.Code)
	}
	target := filepath.Join(dir, "found", "unmask.sqlite")
	step(h.AdminSetupSaveDB, url.Values{"driver": {"sqlite"}, "sqlite_path": {target}})
	step(h.AdminSetupSaveUser, url.Values{
		"username": {"admin"}, "password": {"correct-horse-battery"}, "password_confirm": {"correct-horse-battery"},
	})
	if loc := step(h.AdminSetupInstall, nil); !strings.Contains(loc, "/admin/setup/done") || !strings.Contains(loc, "restart=1") {
		t.Errorf("install -> %q, want the done page with the restart flag", loc)
	}
	if reexecs != 1 {
		t.Errorf("%d re-exec(s) scheduled, want 1", reexecs)
	}
	if h.DB != nil {
		t.Error("the handle was swapped in under the requests; the re-exec is what binds it")
	}
	saved, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.DB.SQLitePath != target {
		t.Errorf("config.yml names %q, want the database the wizard was given", saved.DB.SQLitePath)
	}
	conn, err := db.Open(saved.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if n, err := user.New(conn).Count(context.Background()); err != nil || n != 1 {
		t.Errorf("admins in the new database: %d (%v), want 1", n, err)
	}
}
