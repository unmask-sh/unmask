package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The rate-limit window is forward-auth's alone (the nginx module counts per
// minute), and forward-auth is frozen: the form no longer shows the window, so
// a save must keep what is stored rather than reset it to the 60 s default.
func TestRateLimitSaveKeepsStoredWindow(t *testing.T) {
	form := func(vals url.Values) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=rate-limit",
			strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = r.ParseForm()
		return r
	}
	c := settings.RateLimitConfig{
		Default:  settings.RateLimitValues{Name: "unmask_rate", RequestsPerMin: 30, Burst: 10, WindowSec: 20},
		JA4Limit: settings.AxisLimitConfig{Enabled: true, RequestsPerMin: 600, Burst: 100, WindowSec: 30},
		Zones: []settings.RateZone{
			{Name: "api", PathPatterns: []string{"^/api/"}, RequestsPerMin: 5, Burst: 3, WindowSec: 45},
		},
	}
	if err := applyRateLimitForm(&c, form(url.Values{
		"axis_ip_on":      {"1"},
		"axis_ja4_on":     {"1"},
		"axis_ja4_rpm":    {"600"},
		"axis_ja4_burst":  {"100"},
		"axis_ja4_chmode": {"pow_only"},
		"zone_0_name":     {"api"},
		"zone_0_paths":    {"^/api/"},
		"zone_0_rpm":      {"5"},
		"zone_0_burst":    {"3"},
		"zone_0_on":       {"1"},
		"zone_1_name":     {"fresh"},
		"zone_1_paths":    {"^/login"},
		"zone_1_rpm":      {"10"},
		"zone_1_burst":    {"2"},
		"zone_1_on":       {"1"},
	})); err != nil {
		t.Fatalf("save: %v", err)
	}
	if c.Default.WindowSec != 20 {
		t.Errorf("primary axis window = %d, want the stored 20", c.Default.WindowSec)
	}
	if c.JA4Limit.WindowSec != 30 {
		t.Errorf("JA4 axis window = %d, want the stored 30", c.JA4Limit.WindowSec)
	}
	if len(c.Zones) != 2 {
		t.Fatalf("zones = %+v", c.Zones)
	}
	if c.Zones[0].WindowSec != 45 {
		t.Errorf("zone api window = %d, want the stored 45", c.Zones[0].WindowSec)
	}
	if c.Zones[1].WindowSec != 0 || c.Zones[1].ResolvedWindowSec() != 60 {
		t.Errorf("a new zone leaves the window unset (60 s), got %d", c.Zones[1].WindowSec)
	}

	// A caller that still sends the window (an API client, an old page) sets it.
	if err := applyRateLimitForm(&c, form(url.Values{
		"axis_ip_on":    {"1"},
		"zone_0_name":   {"api"},
		"zone_0_paths":  {"^/api/"},
		"zone_0_rpm":    {"5"},
		"zone_0_burst":  {"3"},
		"zone_0_window": {"15"},
		"zone_0_on":     {"1"},
	})); err != nil {
		t.Fatalf("save: %v", err)
	}
	if c.Zones[0].WindowSec != 15 {
		t.Errorf("a posted window should still be taken, got %d", c.Zones[0].WindowSec)
	}
}

// The settings page no longer shows the window, nor badges the log feed as
// native-only (there is one mode to document now).
func TestSettingsPageDropsForwardAuthOnlyFields(t *testing.T) {
	var base settings.Settings
	base.Server.BasePath = "/unmask"
	base.RateLimit.Zones = []settings.RateZone{
		{Name: "api", PathPatterns: []string{"^/api/"}, RequestsPerMin: 5, Burst: 3, WindowSec: 45},
	}
	h := newTestHandler(t)
	h.SetSettings(base)
	// Each tab's own section must be there, or the absences below prove nothing.
	present := map[string]string{"rate-limit": `name="axis_ip_rpm"`, "retention": `name="nginx_log_enabled"`}
	for _, tab := range []string{"rate-limit", "retention"} {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/"+tab, nil)
		req.SetPathValue("tab", tab)
		req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s tab: %d", tab, rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "</html>") {
			t.Fatalf("%s tab: the page did not render to the end", tab)
		}
		if !strings.Contains(body, present[tab]) {
			t.Fatalf("%s tab: %s is missing -- the section did not render", tab, present[tab])
		}
		for _, gone := range []string{"_window\"", "zv-window", "rl-window-help", "nginx native only", "forward-auth"} {
			if strings.Contains(body, gone) {
				t.Errorf("%s tab still carries %q", tab, gone)
			}
		}
	}
}
