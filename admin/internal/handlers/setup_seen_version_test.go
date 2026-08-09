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
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// driveWizardInstall walks the whole wizard (token -> db -> user -> install)
// on a fresh sqlite install and returns the config that Save wrote.
func driveWizardInstall(t *testing.T, version string) settings.Settings {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "unmask.sqlite")
	cfgPath := filepath.Join(dir, "config.yml")

	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	h := &Handler{DB: conn, ConfigPath: cfgPath, Version: version}
	h.SetSettings(settings.Settings{DB: settings.DB{Driver: "sqlite", SQLitePath: dbPath}})

	token := "tok-seenver-" + version
	oldPath := SetupTokenPath
	SetupTokenPath = filepath.Join(dir, ".setup-token")
	t.Cleanup(func() { SetupTokenPath = oldPath; dropWizardState(token) })
	if err := os.WriteFile(SetupTokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}

	post := func(fn http.HandlerFunc, form url.Values) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/unmask/admin/setup/x", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(setupTokenCookie(token))
		w := httptest.NewRecorder()
		fn(w, r)
		if w.Code != http.StatusFound {
			t.Fatalf("step %T: want 302, got %d: %s", fn, w.Code, w.Body.String())
		}
	}
	post(h.AdminSetupSaveDB, url.Values{"driver": {"sqlite"}, "sqlite_path": {dbPath}})
	post(h.AdminSetupSaveUser, url.Values{
		"username": {"admin"}, "password": {"correct-horse-battery"}, "password_confirm": {"correct-horse-battery"},
	})
	post(h.AdminSetupInstall, nil)

	s, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatalf("re-read config: %v", err)
	}
	return s
}

// TestWizardStampsSeenVersion: a fresh install has no prior behaviour to
// preserve, so the presets its own release ships with must be active from the
// start.  The NEW gate compares each preset's AddedIn against
// nginx.seen_version, and nothing stamped that on installs which never ran
// config-init -- they sat at the v0.1 epoch, which gated off every
// post-v0.1.0 preset.  Found on a wiped install of 0.1.25: four official
// crawler ranges (Applebot, Amazonbot, DuckAssistBot, Perplexity-user) showed
// OFF out of the box.  Their geo ranges were in fact still rendered (that
// path never consulted the gate), so the real damage was the UI contradicting
// the enforcement, the range-verified crawler badges reading unverified, and
// -- for preset axes that DO gate at render (paths / honeypots / targets /
// verdicts) -- post-v0.1.0 entries being genuinely inert on fresh installs.
func TestWizardStampsSeenVersion(t *testing.T) {
	s := driveWizardInstall(t, "0.9.9")
	if s.Nginx.SeenVersion != "v0.9.9" {
		t.Fatalf("seen_version = %q, want the installing release v0.9.9", s.Nginx.SeenVersion)
	}
	// The observable consequence: every shipped range preset is active, so
	// the two-stage crawler rescue works for the 0.1.7 additions too.
	for _, pattern := range []string{`Applebot`, `Amazonbot`} {
		if !nginxconf.RangePresetsActive(s.Nginx, pattern) {
			t.Errorf("%s ranges inactive on a fresh install", pattern)
		}
	}
}

// TestWizardDevBuildDoesNotStamp: "vdev" is unparseable, and the gate treats
// an unparseable seen_version as "nothing is ever new" -- writing it would
// permanently disable upgrade protection on that install.  Leave the field
// alone instead.
func TestWizardDevBuildDoesNotStamp(t *testing.T) {
	s := driveWizardInstall(t, "dev")
	if s.Nginx.SeenVersion == "vdev" {
		t.Fatal("a dev build stamped an unparseable seen_version, disabling the NEW gate forever")
	}
}
