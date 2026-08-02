package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// migratedSQLite creates a database in the state a package install leaves
// behind: schema applied and traffic already recorded, because the daemon
// starts and runs before anyone opens the wizard.
func migratedSQLite(t *testing.T, events int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "unmask.sqlite")
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < events; i++ {
		if _, err := conn.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,x'7f000001','','','',0,'check',0,0,'','','{}',datetime('now'))`); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// TestDetectExistingDBFindsAMigratedDatabase: the wizard can only offer to keep
// a database if it can recognise one.
func TestDetectExistingDBFindsAMigratedDatabase(t *testing.T) {
	path := migratedSQLite(t, 7)
	got := detectExistingDB(settings.DB{Driver: "sqlite", SQLitePath: path})
	if got == nil {
		t.Fatal("a migrated database was not recognised")
	}
	if got.Events != 7 {
		t.Errorf("Events = %d, want 7 -- the count is the operator's evidence it is theirs", got.Events)
	}
	if got.Location != path {
		t.Errorf("Location = %q, want the configured path", got.Location)
	}
}

// TestDetectExistingDBIgnoresAnUnmigratedFile: an empty or foreign SQLite file
// has nothing to keep, and offering to "keep" it would be a lie.
func TestDetectExistingDBIgnoresAnUnmigratedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.sqlite")
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectExistingDB(settings.DB{Driver: "sqlite", SQLitePath: path}); got != nil {
		t.Errorf("an unmigrated file was offered as an existing database: %+v", got)
	}
}

// TestDetectExistingDBDoesNotCreateTheFile: db.Open creates a missing SQLite
// file.  A probe that does that would report "found an existing database" on a
// genuinely fresh install -- having just created the thing it found -- and
// leave a stray file behind when the operator picks MariaDB.
func TestDetectExistingDBDoesNotCreateTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.sqlite")
	if got := detectExistingDB(settings.DB{Driver: "sqlite", SQLitePath: path}); got != nil {
		t.Errorf("a nonexistent path was reported as an existing database: %+v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("detection created the database file it was asked to look for")
	}
}

// setupHandlerWithDB builds a wizard handler whose on-disk config points at
// path, with the setup token present so the wizard is reachable.
func setupHandlerWithDB(t *testing.T, path string) *Handler {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, ".setup-token")
	if err := os.WriteFile(tok, []byte("tok-abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, oldLegacy := SetupTokenPath, legacySetupTokenPath
	SetupTokenPath, legacySetupTokenPath = tok, ""
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = old, oldLegacy })

	h := newTestHandler(t)
	cfgPath := filepath.Join(dir, "config.yml")
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	s.Secret.BVSecret = "test-secret"
	if path != "" {
		s.DB = settings.DB{Driver: "sqlite", SQLitePath: path}
	}
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)
	return h
}

// renderDBStep drives the wizard's DB step and returns its HTML.
func renderDBStep(t *testing.T, h *Handler) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/setup/?step=db", nil)
	r.AddCookie(&http.Cookie{Name: SetupTokenCookieName, Value: "tok-abc"})
	rr := httptest.NewRecorder()
	h.AdminSetupIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("setup step status %d", rr.Code)
	}
	return rr.Body.String()
}

// checkedDriver reports which driver radio the page renders as checked.
func checkedDriver(body string) string {
	m := regexp.MustCompile(`<input type="radio" name="driver" value="([a-z]+)" checked>`).FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

// TestDBStepLeadsWithTheExistingDatabase: a package install reaches the wizard
// with its database already built and recording.  Presenting only "SQLite or
// MariaDB" there reads as "pick one and create it", which is the one thing the
// operator must not believe about a database already holding their traffic.
func TestDBStepLeadsWithTheExistingDatabase(t *testing.T) {
	path := migratedSQLite(t, 42)
	body := renderDBStep(t, setupHandlerWithDB(t, path))

	if !strings.Contains(body, `value="existing"`) {
		t.Fatal("the DB step offers no way to keep the database already in use")
	}
	if got := checkedDriver(body); got != "existing" {
		t.Errorf("pre-selected driver = %q, want \"existing\"", got)
	}
	// The operator has to be able to tell it is *their* database.
	if !strings.Contains(body, path) {
		t.Error("the card does not say which database it means")
	}
	if !strings.Contains(body, "42") {
		t.Error("the card does not show what is already recorded in it")
	}
}

// TestDBStepOnAFreshInstallIsUnchanged: with nothing to keep, the step stays
// the plain driver choice it has always been.
func TestDBStepOnAFreshInstallIsUnchanged(t *testing.T) {
	body := renderDBStep(t, setupHandlerWithDB(t, filepath.Join(t.TempDir(), "nope.sqlite")))

	if strings.Contains(body, `value="existing"`) {
		t.Error("a fresh install is offered a database to keep")
	}
	if got := checkedDriver(body); got != "sqlite" {
		t.Errorf("pre-selected driver = %q, want \"sqlite\"", got)
	}
}

// TestOnlyOneDriverRendersChecked: two checked radios in one group silently
// resolve to the last one in document order, which would hand the choice back
// to SQLite while the page shows the existing card selected.
func TestOnlyOneDriverRendersChecked(t *testing.T) {
	body := renderDBStep(t, setupHandlerWithDB(t, migratedSQLite(t, 1)))
	if n := strings.Count(body, `name="driver"`); n < 3 {
		t.Fatalf("expected three driver radios, found %d", n)
	}
	if n := regexp.MustCompile(`name="driver" value="[a-z]+" checked`).FindAllString(body, -1); len(n) != 1 {
		t.Errorf("%d radios render checked (%v), want exactly 1", len(n), n)
	}
}

// postDriver submits the DB step and returns the redirect target.
func postDriver(t *testing.T, h *Handler, driver string) string {
	t.Helper()
	form := url.Values{"driver": {driver}}
	r := httptest.NewRequest(http.MethodPost, "/unmask/admin/setup/db", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: SetupTokenCookieName, Value: "tok-abc"})
	rr := httptest.NewRecorder()
	h.AdminSetupSaveDB(rr, r)
	return rr.Header().Get("Location")
}

// TestKeepingTheExistingDatabaseAdvancesTheWizard: choosing it must carry the
// configured database forward, not an empty one.
func TestKeepingTheExistingDatabaseAdvancesTheWizard(t *testing.T) {
	path := migratedSQLite(t, 3)
	h := setupHandlerWithDB(t, path)
	// Prime wizard state the way the token step does.
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/setup/", nil)
	r.AddCookie(&http.Cookie{Name: SetupTokenCookieName, Value: "tok-abc"})
	st := h.getWizardState(r)
	if st == nil {
		t.Fatal("no wizard state")
	}

	if loc := postDriver(t, h, "existing"); strings.Contains(loc, "err=") {
		t.Fatalf("keeping the existing database failed: %s", loc)
	}
	if !st.DBSet {
		t.Fatal("the wizard did not record a database choice")
	}
	if st.DB.SQLitePath != path {
		t.Errorf("recorded path = %q, want the configured %q", st.DB.SQLitePath, path)
	}
}

// TestExistingIsRejectedWhenTheDatabaseIsGone: the rendered page is not the
// authority on what is on disk.  A posted "existing" against a database that
// has since vanished must fail rather than commit a config pointing at nothing.
func TestExistingIsRejectedWhenTheDatabaseIsGone(t *testing.T) {
	path := migratedSQLite(t, 1)
	h := setupHandlerWithDB(t, path)
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/setup/", nil)
	r.AddCookie(&http.Cookie{Name: SetupTokenCookieName, Value: "tok-abc"})
	h.getWizardState(r)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if loc := postDriver(t, h, "existing"); !strings.Contains(loc, "err=") {
		t.Errorf("a vanished database was accepted; redirect = %s", loc)
	}
}
