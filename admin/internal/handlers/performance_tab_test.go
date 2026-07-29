package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

var perfEstRE = regexp.MustCompile(`(?s)value="(conservative|standard|generous)".{0,90}?data-est="([^"]+)"`)

// The performance tab exists so an operator can see what their own box resolved
// and pick a different resource level.  Two properties make it useful, and both
// have already been broken once during development:
//   - the profiles must produce DIFFERENT estimates on this host (a single
//     shared ceiling once flattened all three into the same number, which makes
//     the picker meaningless on a large server);
//   - the estimates must be rendered server-side, so the page cannot drift from
//     the budget rule the daemon actually applies.
func TestPerformanceTabProfiles(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=performance", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("performance tab: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	est := map[string]string{}
	for _, m := range perfEstRE.FindAllStringSubmatch(body, -1) {
		est[m[1]] = m[2]
	}
	for _, id := range []string{"conservative", "standard", "generous"} {
		if est[id] == "" {
			t.Fatalf("profile %q has no server-rendered estimate", id)
		}
	}
	if est["conservative"] == est["standard"] || est["standard"] == est["generous"] {
		t.Errorf("profiles collapse to the same estimate (%q / %q / %q) -- the picker cannot guide a choice",
			est["conservative"], est["standard"], est["generous"])
	}
	// Custom fields + the write-batching knobs live here too.
	for _, want := range []string{`name="db_max_conns"`, `name="sqlite_cache_mb"`, `name="events_batch_size"`, `name="events_batch_interval_ms"`} {
		if !strings.Contains(body, want) {
			t.Errorf("performance tab missing %q", want)
		}
	}
	// Restart caveat: the DSN is fixed when the pool opens.
	if !strings.Contains(body, "再起動") {
		t.Error("performance tab must say the change needs a restart")
	}
}

// Saving the tab must persist the profile and custom fields, and flag restart.
func TestPerformanceTabSave(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := dir + "/config.yml"
	s := *h.cfg()
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	h.ConfigPath = cfgPath

	post := func(v url.Values) settings.Settings {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/?section=performance", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("save: want 302, got %d (%s)", rr.Code, rr.Body.String())
		}
		if loc := rr.Header().Get("Location"); !strings.Contains(loc, "restart=1") {
			t.Errorf("DB sizing is start-only, so save must flag restart; Location=%q", loc)
		}
		got, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	got := post(url.Values{
		"perf_profile":             {"custom"},
		"sqlite_cache_mb":          {"96"},
		"db_max_conns":             {"3"},
		"events_batch_size":        {"200"},
		"events_batch_interval_ms": {"250"},
	})
	if got.DB.ResolvedPerfProfile() != settings.PerfProfileCustom {
		t.Errorf("profile = %q, want custom", got.DB.ResolvedPerfProfile())
	}
	if got.DB.SQLiteCacheMB != 96 || got.DB.MaxConns != 3 {
		t.Errorf("custom fields = %dMB / %d conns, want 96 / 3", got.DB.SQLiteCacheMB, got.DB.MaxConns)
	}
	if got.EventsBatchSize != 200 || got.EventsBatchIntervalMs != 250 {
		t.Errorf("batch = %d / %dms, want 200 / 250", got.EventsBatchSize, got.EventsBatchIntervalMs)
	}

	// Switching back to an automatic profile must not need the custom fields.
	got = post(url.Values{"perf_profile": {"conservative"}, "events_batch_size": {"100"}, "events_batch_interval_ms": {"1000"}})
	if got.DB.ResolvedPerfProfile() != settings.PerfProfileConservative {
		t.Errorf("profile = %q, want conservative", got.DB.ResolvedPerfProfile())
	}
}
