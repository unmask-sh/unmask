package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAxisExemptPathMatchers pins the per-axis exempt paths (RSS/Atom feeds
// etc.): each list compiles into its OWN matcher -- geo-exempt gates only
// geoDecide, asn-exempt gates only asnDecide -- and neither lands in the full
// bypass matcher.  The separation is the safety property: a feed exempted from
// one network axis must NOT silently skip the other axis, and must NOT become
// a full pass (which would skip honeypot + ja4 = attack surface).  Also pins
// the per-site filter and the disabled-row skip.
func TestAxisExemptPathMatchers(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Nginx.Geo.ExemptPaths = []settings.BypassPath{
			{Path: "^/feed"}, // global, geo axis only
			{Path: "^/atom", Site: "shop.example.com"}, // per-site
			{Path: "^/gone", Disabled: true},           // disabled -> not compiled
		}
		s.Nginx.Asn.ExemptPaths = []settings.BypassPath{
			{Path: "^/rss"}, // global, asn axis only
		}
		s.Nginx.BypassPaths = settings.BypassPathsConfig{
			Paths: []settings.BypassPath{{Path: "^/full-bypass"}},
		}
	})

	pm := h.bypassMatchers(h.cfg(), "")
	// geo list: /feed matches geoExempt ONLY.
	if !matchPath("/feed.xml", pm.geoExempt) {
		t.Error("/feed.xml should be geo-exempt (global rule)")
	}
	if matchPath("/feed.xml", pm.asnExempt) {
		t.Error("/feed is geo-only; must NOT be asn-exempt")
	}
	// asn list: /rss matches asnExempt ONLY.
	if !matchPath("/rss.xml", pm.asnExempt) {
		t.Error("/rss.xml should be asn-exempt (global rule)")
	}
	if matchPath("/rss.xml", pm.geoExempt) {
		t.Error("/rss is asn-only; must NOT be geo-exempt")
	}
	// site filter + disabled rows.
	if matchPath("/atom.xml", pm.geoExempt) {
		t.Error("/atom is shop-only; must not match on the global site")
	}
	if matchPath("/gone", pm.geoExempt) {
		t.Error("disabled row must not be compiled")
	}
	// Separation from full bypass: an axis-exempt feed must NOT land in the
	// full bypass matcher (else it would skip ja4 / honeypot / rate too).
	if matchPath("/feed.xml", pm.bypass) || matchPath("/rss.xml", pm.bypass) {
		t.Error("axis-exempt paths must NOT be in the full bypass matcher")
	}
	if !matchPath("/full-bypass", pm.bypass) {
		t.Error("/full-bypass belongs in the full bypass matcher")
	}
	// Per-site: on shop.example.com the /atom rule activates.
	pmShop := h.bypassMatchers(h.cfg(), "shop.example.com")
	if !matchPath("/atom.xml", pmShop.geoExempt) {
		t.Error("/atom should be geo-exempt on shop.example.com")
	}
}

// TestApplyExemptPathsForm pins the per-tab save: the geo tab's gx_* rows land
// in Geo.ExemptPaths, the asn tab's ax_* rows in Asn.ExemptPaths (Disabled =
// !enabled), and an invalid regex is rejected rather than silently stored.
func TestApplyExemptPathsForm(t *testing.T) {
	form := url.Values{}
	form["gx_path"] = []string{"^/feed"}
	form["gx_title"] = []string{"RSS"}
	form["gx_site"] = []string{""}
	form["gx_enabled"] = []string{"1"}
	form["gx_updated_at"] = []string{"0"}
	form["ax_path"] = []string{"^/atom"}
	form["ax_title"] = []string{""}
	form["ax_site"] = []string{"shop.example.com"}
	form["ax_enabled"] = []string{"0"} // disabled row round-trips
	form["ax_updated_at"] = []string{"0"}
	r := httptest.NewRequest("POST", "/save?section=geo", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	var n settings.Nginx
	if err := applyExemptPathsForm(&n.Geo.ExemptPaths, "gx", r, i18n.LangEN); err != nil {
		t.Fatalf("gx: %v", err)
	}
	if err := applyExemptPathsForm(&n.Asn.ExemptPaths, "ax", r, i18n.LangEN); err != nil {
		t.Fatalf("ax: %v", err)
	}
	if len(n.Geo.ExemptPaths) != 1 || n.Geo.ExemptPaths[0].Path != "^/feed" || n.Geo.ExemptPaths[0].Title != "RSS" || n.Geo.ExemptPaths[0].Disabled {
		t.Errorf("geo rows = %+v, want [^/feed RSS enabled]", n.Geo.ExemptPaths)
	}
	if len(n.Asn.ExemptPaths) != 1 || n.Asn.ExemptPaths[0].Path != "^/atom" || !n.Asn.ExemptPaths[0].Disabled || n.Asn.ExemptPaths[0].Site != "shop.example.com" {
		t.Errorf("asn rows = %+v, want [^/atom disabled shop-only]", n.Asn.ExemptPaths)
	}

	// An invalid regex is rejected (not silently stored).
	bad := url.Values{}
	bad["gx_path"] = []string{"("}
	br := httptest.NewRequest("POST", "/save", strings.NewReader(bad.Encode()))
	br.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = br.ParseForm()
	var n2 settings.Nginx
	if err := applyExemptPathsForm(&n2.Geo.ExemptPaths, "gx", br, i18n.LangEN); err == nil {
		t.Error("invalid regex must be rejected")
	}
}
