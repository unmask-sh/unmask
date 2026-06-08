package handlers

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
