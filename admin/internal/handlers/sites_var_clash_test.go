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

// Two defined sites that fold to one nginx variable segment would render
// two map blocks for one variable and nginx would refuse the configuration;
// the form refuses the save instead, names both hosts, and leaves the stored
// list as it was.
func TestSitesSaveRefusesVariableNameClash(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Sites.Mode = settings.SiteModeDefined
	s.Sites.Defined = []string{"shop.example.com"}
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)

	form := url.Values{}
	form["site_mode"] = []string{"defined"}
	form["site_defined"] = []string{"shop.example.com", "shop-example.com"}
	form["site_defined_enabled"] = []string{"1", "1"}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=sites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	// The error travels in the flash cookie, not the redirect URL.
	msg := ""
	for _, c := range rr.Result().Cookies() {
		if c.Name == flashCookiePrefix+"err" {
			msg, _ = url.QueryUnescape(c.Value)
		}
	}
	if !strings.Contains(msg, "shop.example.com") || !strings.Contains(msg, "shop-example.com") || !strings.Contains(msg, "shop_example_com") {
		t.Fatalf("the clash must be refused naming both hosts and the segment, got err=%q location=%q", msg, rr.Header().Get("Location"))
	}
	saved, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Sites.Defined) != 1 || saved.Sites.Defined[0] != "shop.example.com" {
		t.Errorf("a refused save must leave the list alone, got %v", saved.Sites.Defined)
	}
}
