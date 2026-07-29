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

// Each profile card must show the TOTAL it would use and how that splits across
// the pool -- "how much will this actually take" is the question the tab exists
// to answer, and the connection count is the other half of the picture.
var perfCardRE = regexp.MustCompile(`(?s)value="(conservative|standard|generous)".{0,400}?perf-total">([^<]+)<.{0,200}?perf-split">([^<]+)<`)

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
	// Totals and the pool split must be on every card.
	cards := map[string][2]string{}
	for _, m := range perfCardRE.FindAllStringSubmatch(body, -1) {
		cards[m[1]] = [2]string{m[2], m[3]}
	}
	for _, id := range []string{"conservative", "standard", "generous"} {
		c, ok := cards[id]
		if !ok {
			t.Errorf("profile %q shows no total / split", id)
			continue
		}
		if c[0] == "" || c[0] == "—" {
			t.Errorf("profile %q has no total figure", id)
		}
		// The split carries the connection count, which is what makes the
		// number actionable ("96 MB x 2" vs "12 MB x 16").
		if !strings.Contains(c[1], "x") && !strings.Contains(c[1], "×") {
			t.Errorf("profile %q split %q does not show the per-connection x pool breakdown", id, c[1])
		}
	}

	// The presets are shares of the host's memory, and the UI has to say so:
	// showing only megabytes made them read as fixed sizes, which is what made
	// an extra "automatic" choice seem necessary.  Assert the ratio, the
	// "on this host" framing, and the two groups that separate host-following
	// profiles from the fixed one.
	for _, want := range []string{"メモリの 3%", "メモリの 6%", "メモリの 12%", "この環境では"} {
		if !strings.Contains(body, want) {
			t.Errorf("presets must be presented as a share of host memory; missing %q", want)
		}
	}
	if !strings.Contains(body, `perf-group-h`) || !strings.Contains(body, "環境に合わせて自動調整") || !strings.Contains(body, "固定") {
		t.Error("profiles must be grouped into host-following vs fixed")
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

// A settings tab is reachable only if three things exist together: the nav
// entry, the card on the settings landing page, and the tab body.  They live in
// different parts of settings.html, so adding a tab and forgetting one is easy
// -- and the failure is silent (the tab renders fine via a hand-typed URL while
// being invisible in the UI).  This walks every tab the nav claims and asserts
// the set is consistent, so the next tab cannot ship half-wired.
func TestSettingsTabsFullyWired(t *testing.T) {
	h := newTestHandler(t)
	get := func(tab string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab="+tab, nil)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("tab %q: want 200, got %d", tab, rr.Code)
		}
		return rr.Body.String()
	}
	// The landing page carries both the nav and the tab cards.
	top := get("top")
	navRE := regexp.MustCompile(`<li><a href="\?tab=([a-z-]+)"`)
	cardRE := regexp.MustCompile(`class="sti" href="\?tab=([a-z-]+)"`)

	nav := map[string]bool{}
	for _, m := range navRE.FindAllStringSubmatch(top, -1) {
		nav[m[1]] = true
	}
	cards := map[string]bool{}
	for _, m := range cardRE.FindAllStringSubmatch(top, -1) {
		cards[m[1]] = true
	}
	if len(nav) < 5 {
		t.Fatalf("only %d nav tabs found -- the scrape is broken, not the page", len(nav))
	}
	for tab := range nav {
		if tab == "top" {
			continue
		}
		if !cards[tab] {
			t.Errorf("tab %q is in the nav but has no card on the settings landing page", tab)
		}
		// A tab whose body is missing renders the page without its form; the
		// save button and fields simply vanish.  Probe for any form posting to
		// this tab's section, which every real tab body has.
		body := get(tab)
		if !strings.Contains(body, `settings/save?section=`) {
			t.Errorf("tab %q renders no settings form -- body block missing?", tab)
		}
	}
	// The tab this file is about must be fully wired, explicitly.
	for _, want := range []string{"performance", "retention"} {
		if !nav[want] {
			t.Errorf("tab %q missing from the nav", want)
		}
		if !cards[want] {
			t.Errorf("tab %q missing from the settings landing page", want)
		}
	}
}
