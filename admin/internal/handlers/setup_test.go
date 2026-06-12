package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// An `apt upgrade` (deb "configure") re-mints .setup-token even on an
// already-provisioned box.  SetupNeeded must NOT re-trigger the wizard -- and
// must clear the stale token -- when an admin user already exists, or it
// 302-loops every admin route and re-completing it rewrites the DB block.
func TestSetupNeeded_StaleTokenWithAdminClears(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE unmask_user (id INTEGER PRIMARY KEY, username TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Exec(`INSERT INTO unmask_user (username) VALUES ('admin')`); err != nil {
		t.Fatal(err)
	}
	old := SetupTokenPath
	SetupTokenPath = filepath.Join(t.TempDir(), ".setup-token")
	t.Cleanup(func() { SetupTokenPath = old })
	if err := os.WriteFile(SetupTokenPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	needed, step := h.SetupNeeded(httptest.NewRequest("GET", "/admin/", nil))
	if needed {
		t.Fatalf("setup should not be needed when an admin exists; got needed=%v step=%q", needed, step)
	}
	if _, err := os.Stat(SetupTokenPath); !os.IsNotExist(err) {
		t.Fatalf("stale setup token should have been removed")
	}
}

// Sanity: a genuinely fresh box (token present, no admin row yet) must still
// route to the wizard -- the fix above must not short-circuit a real setup.
func TestSetupNeeded_TokenNoAdminStillWizard(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE unmask_user (id INTEGER PRIMARY KEY, username TEXT)`); err != nil {
		t.Fatal(err)
	}
	old := SetupTokenPath
	SetupTokenPath = filepath.Join(t.TempDir(), ".setup-token")
	t.Cleanup(func() { SetupTokenPath = old })
	if err := os.WriteFile(SetupTokenPath, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}

	needed, _ := h.SetupNeeded(httptest.NewRequest("GET", "/admin/", nil))
	if !needed {
		t.Fatal("setup should be needed on a fresh box with a token and no admin user")
	}
	if _, err := os.Stat(SetupTokenPath); err != nil {
		t.Fatal("token must NOT be removed while setup is genuinely pending")
	}
}

// setupTokenCookie threads the verified setup-token cookie through the wizard
// POSTs (the in-flight state is keyed by the cookie value).
func setupTokenCookie(token string) *http.Cookie {
	return &http.Cookie{Name: SetupTokenCookieName, Value: token}
}

// TestSetupWizardFullInstall drives the whole wizard end to end on the common
// fresh-box SQLite-default path: token -> db -> user -> install, with the
// operator picking the SAME sqlite the daemon already booted on, so install
// REUSES the live connection (no driver switch, no re-exec).  This is the path
// the 2026-06-08 "database is closed" incident lived in, and nothing below the
// SetupNeeded unit tests exercised the commit before.
func TestSetupWizardFullInstall(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "unmask.sqlite")
	cfgPath := filepath.Join(dir, "config.yml")

	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: dbPath})
	if err != nil {
		t.Fatalf("open boot db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	h := &Handler{DB: conn, ConfigPath: cfgPath}
	// The live config names the same DB the daemon booted on, so the install's
	// `s.DB == h.cfg().DB` reuse branch is taken.
	h.SetSettings(settings.Settings{DB: settings.DB{Driver: "sqlite", SQLitePath: dbPath}})

	const token = "tok-fullinstall-3f1a"
	oldPath := SetupTokenPath
	SetupTokenPath = filepath.Join(dir, ".setup-token")
	t.Cleanup(func() { SetupTokenPath = oldPath; dropWizardState(token) })
	if err := os.WriteFile(SetupTokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}

	postForm := func(fn http.HandlerFunc, form url.Values, cookie *http.Cookie) *http.Response {
		r := httptest.NewRequest(http.MethodPost, "/unmask/admin/setup/x", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		fn(w, r)
		return w.Result()
	}

	// 1. token step: correct token -> a setup-token cookie + redirect.
	res := postForm(h.AdminSetupSaveToken, url.Values{"token": {token}}, nil)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("token step: want 302, got %d", res.StatusCode)
	}
	issued := false
	for _, c := range res.Cookies() {
		if c.Name == SetupTokenCookieName && c.Value == token {
			issued = true
		}
	}
	if !issued {
		t.Fatal("token step issued no valid setup-token cookie")
	}

	// 2. db step: sqlite at the same path the daemon already holds.
	res = postForm(h.AdminSetupSaveDB, url.Values{
		"driver":      {"sqlite"},
		"sqlite_path": {dbPath},
	}, setupTokenCookie(token))
	if res.StatusCode != http.StatusFound {
		t.Fatalf("db step: want 302, got %d", res.StatusCode)
	}
	peek := httptest.NewRequest(http.MethodGet, "/x", nil)
	peek.AddCookie(setupTokenCookie(token))
	if st := getWizardState(peek); st == nil || !st.DBSet {
		t.Fatal("db step did not record DBSet in wizard state")
	}

	// 3. user step.
	res = postForm(h.AdminSetupSaveUser, url.Values{
		"username":         {"admin"},
		"password":         {"correct-horse-battery"},
		"password_confirm": {"correct-horse-battery"},
	}, setupTokenCookie(token))
	if res.StatusCode != http.StatusFound {
		t.Fatalf("user step: want 302, got %d", res.StatusCode)
	}

	// 4. install: atomic commit.
	res = postForm(h.AdminSetupInstall, nil, setupTokenCookie(token))
	if res.StatusCode != http.StatusFound {
		t.Fatalf("install: want 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "/admin/setup/done") {
		t.Fatalf("install redirect = %q, want .../admin/setup/done", loc)
	}
	if strings.Contains(loc, "restart=1") {
		t.Fatal("same-DB install must NOT demand a restart (the live conn was reused)")
	}

	// (a) the admin row is created.
	var n int
	if err := h.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM unmask_user WHERE username = 'admin'`).Scan(&n); err != nil {
		t.Fatalf("count admin users: %v", err)
	}
	if n != 1 {
		t.Fatalf("want exactly 1 admin user after install, got %d", n)
	}
	// (b) the wizard is sealed: token file gone, setup no longer needed.
	if _, err := os.Stat(SetupTokenPath); !os.IsNotExist(err) {
		t.Fatal("install must remove the setup token (wizard re-run guard)")
	}
	if needed, _ := h.SetupNeeded(httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)); needed {
		t.Fatal("setup should read as sealed (not needed) after a successful install")
	}
	// (c) config.yml persisted with the chosen DB.
	saved, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if saved.DB.Driver != "sqlite" || saved.DB.SQLitePath != dbPath {
		t.Fatalf("persisted DB = %+v, want sqlite @ %s", saved.DB, dbPath)
	}
}

// TestSetupWizardInstallRejectsIncompleteState guards the deferred-commit
// contract: an install POST that arrives before the user step is collected
// must NOT create a user, persist config, or seal the token -- it bounces back
// to the wizard so the operator can finish.
func TestSetupWizardInstallRejectsIncompleteState(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "unmask.sqlite")
	cfgPath := filepath.Join(dir, "config.yml")

	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: dbPath})
	if err != nil {
		t.Fatalf("open boot db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	h := &Handler{DB: conn, ConfigPath: cfgPath}
	h.SetSettings(settings.Settings{DB: settings.DB{Driver: "sqlite", SQLitePath: dbPath}})

	const token = "tok-incomplete-9c2b"
	oldPath := SetupTokenPath
	SetupTokenPath = filepath.Join(dir, ".setup-token")
	t.Cleanup(func() { SetupTokenPath = oldPath; dropWizardState(token) })
	if err := os.WriteFile(SetupTokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}

	post := func(fn http.HandlerFunc, form url.Values) *http.Response {
		r := httptest.NewRequest(http.MethodPost, "/unmask/admin/setup/x", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(setupTokenCookie(token))
		w := httptest.NewRecorder()
		fn(w, r)
		return w.Result()
	}

	// db step only -- deliberately skip the user step.
	if res := post(h.AdminSetupSaveDB, url.Values{"driver": {"sqlite"}, "sqlite_path": {dbPath}}); res.StatusCode != http.StatusFound {
		t.Fatalf("db step: want 302, got %d", res.StatusCode)
	}
	// install with UserSet == false.
	res := post(h.AdminSetupInstall, nil)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("install: want 302, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); strings.Contains(loc, "/admin/setup/done") {
		t.Fatalf("incomplete install must NOT reach done; got %q", loc)
	}
	// No schema/user was created (the commit never ran).
	var n int
	err = h.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM unmask_user`).Scan(&n)
	if err == nil && n != 0 {
		t.Fatalf("incomplete install created %d user(s)", n)
	}
	// The token must survive so the operator can finish the wizard.
	if _, statErr := os.Stat(SetupTokenPath); statErr != nil {
		t.Fatal("incomplete install must not remove the setup token")
	}
}
