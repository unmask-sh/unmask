package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The About tab's second checkbox switches the scheduled pulls of the crawler
// IP ranges and browser versions: unticked stores sync_disabled, ticked
// clears it, and the page shows the stored state.
func TestAboutSaveSwitchesTheFeedPulls(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	emptyPath := filepath.Join(dir, "empty-seed.yml")
	if err := os.WriteFile(emptyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(loaded)

	save := func(form url.Values) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=about", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
			t.Fatalf("save: %d %q", rr.Code, rr.Header().Get("Location"))
		}
	}
	stored := func() bool {
		t.Helper()
		got, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		return got.Nginx.SyncDisabled
	}
	page := func() string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=about", nil)
		req.SetPathValue("tab", "about")
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		return rr.Body.String()
	}

	if stored() {
		t.Fatal("a fresh install must pull (sync_disabled unset)")
	}
	if !strings.Contains(page(), `name="feed_sync" value="1" checked`) {
		t.Fatal("the checkbox must show ticked while the pulls run")
	}

	save(url.Values{"version_check": {"1"}})
	if !stored() {
		t.Fatal("unticking must store sync_disabled")
	}
	if strings.Contains(page(), `name="feed_sync" value="1" checked`) {
		t.Fatal("the checkbox must show unticked once the pulls are off")
	}

	save(url.Values{"version_check": {"1"}, "feed_sync": {"1"}})
	if stored() {
		t.Fatal("ticking must clear sync_disabled")
	}
}
