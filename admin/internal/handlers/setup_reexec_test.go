package handlers

import (
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

// TestSetupWizardDBSwitchTriggersReexec: completing the wizard onto a
// DIFFERENT database must schedule the self-restart and flag the done page
// (?restart=1).  This is the 2026-06-10 GA bug class: the boot handle closes,
// the background workers keep holding it, and funnel + serve recording break
// silently until a restart -- the auto re-exec is the fix, so its trigger
// gets pinned.  The same-DB path (no re-exec, no restart flag) is pinned by
// TestSetupWizardFullInstall.
func TestSetupWizardDBSwitchTriggersReexec(t *testing.T) {
	dir := t.TempDir()
	bootPath := filepath.Join(dir, "boot.sqlite")
	newPath := filepath.Join(dir, "switched.sqlite")
	cfgPath := filepath.Join(dir, "config.yml")

	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: bootPath})
	if err != nil {
		t.Fatalf("open boot db: %v", err)
	}
	// No Close cleanup for conn: a successful switch closes the boot handle.

	h := &Handler{DB: conn, ConfigPath: cfgPath}
	h.SetSettings(settings.Settings{DB: settings.DB{Driver: "sqlite", SQLitePath: bootPath}})

	fired := 0
	prev := scheduleReexecFn
	scheduleReexecFn = func() { fired++ }
	t.Cleanup(func() { scheduleReexecFn = prev })

	const token = "tok-dbswitch-77aa"
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

	if res := postForm(h.AdminSetupSaveToken, url.Values{"token": {token}}, nil); res.StatusCode != http.StatusFound {
		t.Fatalf("token step: want 302, got %d", res.StatusCode)
	}
	if res := postForm(h.AdminSetupSaveDB, url.Values{
		"driver":      {"sqlite"},
		"sqlite_path": {newPath}, // NOT the boot path: this is the switch
	}, setupTokenCookie(token)); res.StatusCode != http.StatusFound {
		t.Fatalf("db step: want 302, got %d", res.StatusCode)
	}
	if res := postForm(h.AdminSetupSaveUser, url.Values{
		"username":         {"admin"},
		"password":         {"correct-horse-battery"},
		"password_confirm": {"correct-horse-battery"},
	}, setupTokenCookie(token)); res.StatusCode != http.StatusFound {
		t.Fatalf("user step: want 302, got %d", res.StatusCode)
	}

	res := postForm(h.AdminSetupInstall, nil, setupTokenCookie(token))
	if res.StatusCode != http.StatusFound {
		t.Fatalf("install: want 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "restart=1") {
		t.Fatalf("a DB switch must flag the done page for restart, got Location=%q", loc)
	}
	if fired != 1 {
		t.Fatalf("a DB switch must schedule the re-exec exactly once, fired=%d", fired)
	}
	if h.DB == conn {
		t.Fatal("install did not swap the live handle to the new DB")
	}
}
