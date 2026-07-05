package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Sites = settings.SiteAcceptanceConfig{Mode: settings.SiteModeAuto} })
	if g := h.ghostSites(ctx, 24); len(g) != 0 {
		t.Fatalf("auto mode: want 0 ghosts, got %d", len(g))
	}

	// defined mode, shop defined: blog is the only ghost.
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Sites = settings.SiteAcceptanceConfig{
			Mode:    settings.SiteModeDefined,
			Defined: []string{"shop.example.com"},
		}
	})
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
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Sites = settings.SiteAcceptanceConfig{
			Mode:    settings.SiteModeDefined,
			Defined: []string{"shop.example.com", "blog.example.com"},
		}
	})
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
			`INSERT INTO unmask_event (site, host, ip_address, phase) VALUES (?, ?, ?, 'serve')`,
			s, "edge-tokyo-1", ip); err != nil {
			t.Fatalf("insert %s: %v", s, err)
		}
	}
	// defined mode with only shop defined -> blog is the lone ghost.
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Sites = settings.SiteAcceptanceConfig{
			Mode:    settings.SiteModeDefined,
			Defined: []string{"shop.example.com"},
		}
	})

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
	// the host inventory section lists every observed unmask instance, with a
	// disable toggle per row.
	if !strings.Contains(body, "edge-tokyo-1") {
		t.Errorf("host inventory missing the observed host")
	}
	if !strings.Contains(body, "/admin/api/hosts/toggle") {
		t.Errorf("host inventory missing the disable/enable toggle")
	}
	// the self host-id editor lives in the multi-host section.
	if !strings.Contains(body, `name="host_id"`) {
		t.Errorf("sites tab missing the editable host-id field")
	}
	// the whole tab is a single settings form (host id + site acceptance) ->
	// exactly one save form, so one Save button.
	if n := strings.Count(body, "save?section=sites"); n != 1 {
		t.Errorf("want exactly 1 settings-save form on the sites tab, got %d", n)
	}
	// The shared header_tools partial must put the host + site pickers on the
	// settings page too (regression: they used to be dashboard-only).
	for _, want := range []string{"host-picker", "site-picker"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings header missing the %q", want)
		}
	}
	// shop is defined, so only blog should carry a one-click promote button.
	if n := strings.Count(body, "data-site="); n != 1 {
		t.Errorf("want exactly 1 ghost promote button, got %d", n)
	}
}

// TestApplySitesForm checks the "sites" tab save handler: mode coercion plus
// normalization and de-duplication of the defined-list textarea.
func TestApplySitesForm(t *testing.T) {
	c := &settings.SiteAcceptanceConfig{}
	// site_defined is now a value-rule-list: one host per repeated field rather
	// than a newline textarea.  Split the fixture on \n and pass each row.
	form := func(mode, defined string) *http.Request {
		vals := url.Values{}
		vals.Set("site_mode", mode)
		for _, line := range strings.Split(defined, "\n") {
			vals.Add("site_defined", line)
		}
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(vals.Encode()))
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

// TestAdminHostToggle disables then re-enables a host and checks the disabled
// list round-trips through the config file.
func TestAdminHostToggle(t *testing.T) {
	h := newTestHandler(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(settings.Settings{}, cfgPath); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	h.ConfigPath = cfgPath

	post := func(host, op string) {
		r := httptest.NewRequest(http.MethodPost, "/x",
			strings.NewReader("host="+host+"&op="+op))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.AdminHostToggle(httptest.NewRecorder(), r)
	}

	post("retired-1", "disable")
	if !h.cfg().Hosts.IsDisabled("retired-1") {
		t.Fatalf("disable: retired-1 not in disabled list: %v", h.cfg().Hosts.Disabled)
	}
	// idempotent: disabling twice keeps a single entry.
	post("retired-1", "disable")
	if n := len(h.cfg().Hosts.Disabled); n != 1 {
		t.Errorf("disable twice: want 1 entry, got %d", n)
	}
	// persisted to disk.
	if reloaded, err := settings.Load(cfgPath); err != nil {
		t.Fatalf("reload: %v", err)
	} else if !reloaded.Hosts.IsDisabled("retired-1") {
		t.Errorf("disabled host not persisted to config")
	}

	post("retired-1", "enable")
	if h.cfg().Hosts.IsDisabled("retired-1") {
		t.Errorf("enable: retired-1 still disabled")
	}

	// a junk host id is rejected (charset guard).
	post("bad host!", "disable")
	if len(h.cfg().Hosts.Disabled) != 0 {
		t.Errorf("junk host id should be rejected, got %v", h.cfg().Hosts.Disabled)
	}
}

// TestSitePickerExcludesGhosts: in "defined" mode the site picker lists only
// the defined sites — a ghost (undefined Host) must not pollute the dropdown.
// A ghost selected via cookie is still shown as a flagged extra option.
func TestSitePickerExcludesGhosts(t *testing.T) {
	h := newTestHandler(t)
	ip := []byte{1, 2, 3, 4}
	for _, s := range []string{"shop.example.com", "blog.example.com"} {
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_event (site, ip_address, phase) VALUES (?, ?, 'serve')`,
			s, ip); err != nil {
			t.Fatalf("insert %s: %v", s, err)
		}
	}

	// auto mode: every observed site is listed.
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Sites = settings.SiteAcceptanceConfig{Mode: settings.SiteModeAuto} })
	d := map[string]any{}
	h.addMeToData(httptest.NewRequest(http.MethodGet, "/x", nil), d)
	if opts, _ := d["SitePickerOptions"].([]string); len(opts) != 2 {
		t.Errorf("auto mode: want 2 picker options, got %v", opts)
	}

	// defined mode: only the defined site; the ghost (blog) is excluded.
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Sites = settings.SiteAcceptanceConfig{
			Mode: settings.SiteModeDefined, Defined: []string{"shop.example.com"},
		}
	})
	d = map[string]any{}
	h.addMeToData(httptest.NewRequest(http.MethodGet, "/x", nil), d)
	opts, _ := d["SitePickerOptions"].([]string)
	if len(opts) != 1 || opts[0] != "shop.example.com" {
		t.Errorf("defined mode: want [shop.example.com], got %v", opts)
	}

	// a ghost selected via cookie stays visible as a flagged extra option.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: "unmask_site", Value: "blog.example.com"})
	d = map[string]any{}
	h.addMeToData(r, d)
	if d["SiteSelectedExtra"] != true || d["SiteSelectedGhost"] != true {
		t.Errorf("ghost cookie: SiteSelectedExtra=%v SiteSelectedGhost=%v, want both true",
			d["SiteSelectedExtra"], d["SiteSelectedGhost"])
	}
}
