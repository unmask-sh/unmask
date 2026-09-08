package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// postSites submits the Sites tab form with the given defined rows and returns
// the flash error (empty when the save went through).
func postSites(t *testing.T, h *Handler, rows []string) string {
	t.Helper()
	form := url.Values{}
	form["site_mode"] = []string{"defined"}
	form["site_defined"] = rows
	ens := make([]string, len(rows))
	for i := range ens {
		ens[i] = "1"
	}
	form["site_defined_enabled"] = ens
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=sites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	for _, c := range rr.Result().Cookies() {
		if c.Name == flashCookiePrefix+"err" {
			msg, _ := url.QueryUnescape(c.Value)
			return msg
		}
	}
	return ""
}

// A defined-site row carrying a pattern-mode marker (or a scheme) is refused
// by name.  normalizeSite reads "contains:shop.example.com" as host:port and
// keeps the word before the colon, which is how a site saved as "contains"
// between 0.1.25 and 0.1.40 (the value-list chip added the marker to every
// new row).  A numeric :port is still fine: normalizeSite strips it.
func TestSitesSaveRefusesModeMarker(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Sites.Mode = settings.SiteModeDefined
	s.Sites.Defined = []string{"shop.example.com"}
	// A successful save re-renders the nginx snippets; point that at a temp
	// dir so the accepted case below does not fail on /var/lib/unmask.
	s.Nginx.OutputDir = filepath.Join(t.TempDir(), "nginx")
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)

	for _, bad := range []string{"contains:shop2.example.com", "exact:shop2.example.com", "https://shop2.example.com"} {
		msg := postSites(t, h, []string{"shop.example.com", bad})
		if !strings.Contains(msg, bad) {
			t.Errorf("%q must be refused naming the value, got err=%q", bad, msg)
		}
		saved, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if len(saved.Sites.Defined) != 1 || saved.Sites.Defined[0] != "shop.example.com" {
			t.Errorf("a refused save must leave the list alone, got %v after %q", saved.Sites.Defined, bad)
		}
	}

	if msg := postSites(t, h, []string{"shop.example.com", "shop2.example.com:8080"}); msg != "" {
		t.Fatalf("a numeric port is not a marker, got err=%q", msg)
	}
	saved, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Sites.Defined) != 2 || saved.Sites.Defined[1] != "shop2.example.com" {
		t.Errorf("want the port stripped and the host kept, got %v", saved.Sites.Defined)
	}
}

// The pattern-mode chip renders only on a value list that names a mode set
// (admin_allowed_hosts).  Defined sites, admin IPs and the metrics allowlist
// are hosts and addresses, not regexes: no chip, so no marker can ride into
// the value.
func TestValueListsHaveNoPatternModeChip(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Sites = settings.SiteAcceptanceConfig{Mode: settings.SiteModeDefined, Defined: []string{"shop.example.com"}}
	})
	render := func(tab string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab="+tab, nil)
		req.SetPathValue("tab", tab)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("tab %s: want 200, got %d", tab, rr.Code)
		}
		return rr.Body.String()
	}
	// list returns the markup from one rule list's opening tag up to the next
	// rule list on the page (the list's rows and its <template> included).
	list := func(body, name string) string {
		i := strings.Index(body, `data-rule-name="`+name+`"`)
		if i < 0 {
			t.Fatalf("rule list %s not rendered", name)
		}
		rest := body[i+1:]
		// Up to the next list, or the page scripts (which mention the chip's
		// class name in code), whichever comes first.
		for _, stop := range []string{`data-rule-name="`, "<script"} {
			if j := strings.Index(rest, stop); j >= 0 {
				rest = rest[:j]
			}
		}
		return rest
	}
	if strings.Contains(list(render("sites"), "site_defined"), "rule-pat-mode") {
		t.Errorf("site_defined must not render the pattern-mode chip")
	}
	network := render("network")
	if !strings.Contains(list(network, "admin_allowed_hosts"), "rule-pat-mode") {
		t.Errorf("admin_allowed_hosts keeps its host-mode chip")
	}
	for _, name := range []string{"admin_allowed_ips", "metrics_allow_from"} {
		if strings.Contains(list(network, name), "rule-pat-mode") {
			t.Errorf("%s must not render the pattern-mode chip", name)
		}
	}
}
