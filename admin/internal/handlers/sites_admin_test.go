package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestGhostSites checks the ghost-site classification: in "defined" mode an
// observed site that is not in Sites.Defined is a ghost; in "auto" mode nothing
// is a ghost; a defined site never is.
func TestGhostSites(t *testing.T) {
	h := newTestHandler(t)
	ip := []byte{1, 2, 3, 4}
	for _, site := range []string{"shop.example.com", "shop.example.com", "blog.example.com"} {
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_event (site, ip_address, phase) VALUES (?, ?, 'serve')`,
			site, ip); err != nil {
			t.Fatalf("insert %s: %v", site, err)
		}
	}
	ctx := context.Background()

	// auto mode: no ghosts.
	h.Settings.Sites = settings.SiteAcceptanceConfig{Mode: settings.SiteModeAuto}
	if g := h.ghostSites(ctx, 24); len(g) != 0 {
		t.Fatalf("auto mode: want 0 ghosts, got %d", len(g))
	}

	// defined mode, shop defined: blog is the only ghost.
	h.Settings.Sites = settings.SiteAcceptanceConfig{
		Mode:    settings.SiteModeDefined,
		Defined: []string{"shop.example.com"},
	}
	g := h.ghostSites(ctx, 24)
	if len(g) != 1 {
		t.Fatalf("defined mode: want 1 ghost, got %d (%+v)", len(g), g)
	}
	if g[0].Site != "blog.example.com" {
		t.Errorf("ghost site = %q, want blog.example.com", g[0].Site)
	}
	if g[0].Events != 1 {
		t.Errorf("ghost events = %d, want 1", g[0].Events)
	}

	// defined mode, both defined: no ghosts.
	h.Settings.Sites = settings.SiteAcceptanceConfig{
		Mode:    settings.SiteModeDefined,
		Defined: []string{"shop.example.com", "blog.example.com"},
	}
	if g := h.ghostSites(ctx, 24); len(g) != 0 {
		t.Fatalf("all defined: want 0 ghosts, got %d", len(g))
	}
}

// TestSettingsSitesTabRender exercises the full render path of the settings
// "sites" tab: the acceptance-mode form, the defined-list textarea, and the
// ghost report with its one-click promote forms.
func TestSettingsSitesTabRender(t *testing.T) {
	h := newTestHandler(t)
	ip := []byte{1, 2, 3, 4}
	for _, s := range []string{"shop.example.com", "blog.example.com"} {
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_event (site, ip_address, phase) VALUES (?, ?, 'serve')`,
			s, ip); err != nil {
			t.Fatalf("insert %s: %v", s, err)
		}
	}
	// defined mode with only shop defined -> blog is the lone ghost.
	h.Settings.Sites = settings.SiteAcceptanceConfig{
		Mode:    settings.SiteModeDefined,
		Defined: []string{"shop.example.com"},
	}

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=sites", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"site_mode", "site_defined", "blog.example.com", "/admin/api/sites/promote"} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered sites tab missing %q", want)
		}
	}
	// shop is defined, so only blog should carry a promote form.
	if n := strings.Count(body, `name="site" value=`); n != 1 {
		t.Errorf("want exactly 1 ghost promote form, got %d", n)
	}
}

// TestApplySitesForm checks the "sites" tab save handler: mode coercion plus
// normalization and de-duplication of the defined-list textarea.
func TestApplySitesForm(t *testing.T) {
	c := &settings.SiteAcceptanceConfig{}
	form := func(mode, defined string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(
			"site_mode="+mode+"&site_defined="+strings.ReplaceAll(defined, "\n", "%0A")))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}

	applySitesForm(c, form("defined", "Shop.Example.com:8443\n\nblog.example.com\nshop.example.com\n"))
	if c.Mode != settings.SiteModeDefined {
		t.Errorf("mode = %q, want defined", c.Mode)
	}
	// lowercased + port-stripped + de-duplicated + blank lines dropped.
	want := []string{"shop.example.com", "blog.example.com"}
	if len(c.Defined) != len(want) {
		t.Fatalf("defined = %v, want %v", c.Defined, want)
	}
	for i := range want {
		if c.Defined[i] != want[i] {
			t.Errorf("defined[%d] = %q, want %q", i, c.Defined[i], want[i])
		}
	}

	// any non-"defined" mode value coerces to auto.
	applySitesForm(c, form("garbage", ""))
	if c.Mode != settings.SiteModeAuto {
		t.Errorf("mode = %q, want auto", c.Mode)
	}
}
