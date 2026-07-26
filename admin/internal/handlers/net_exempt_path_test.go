package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestNetExemptPathMatcher pins that a net-exempt path (RSS/Atom feeds etc.)
// compiles into its OWN matcher, separate from the full bypass matcher. In the
// AuthCheck default case this matcher gates only geoDecide/asnDecide, so the
// path drops the geo/asn axis while ja4 / honeypot / ua / rate / ban still run.
// The separation is the safety property: a feed exempted from geo/asn must NOT
// silently become a full pass (which would skip honeypot + ja4 = attack surface).
// Also pins the per-site filter and the disabled-row skip.
func TestNetExemptPathMatcher(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Nginx.NetExemptPaths = settings.NetExemptPathsConfig{
			Paths: []settings.BypassPath{
				{Path: "^/feed"}, // global
				{Path: "^/atom", Site: "shop.example.com"}, // per-site
				{Path: "^/disabled", Disabled: true},       // disabled -> not compiled
			},
		}
		s.Nginx.BypassPaths = settings.BypassPathsConfig{
			Paths: []settings.BypassPath{{Path: "^/full-bypass"}},
		}
	})

	// Global site: /feed is net-exempt; the shop-only /atom is not; the disabled
	// row is not; an unrelated path is not.
	pm := h.bypassMatchers(h.cfg(), "")
	if !matchPath("/feed.xml", pm.netExempt) {
		t.Error("/feed.xml should be net-exempt (global rule)")
	}
	if matchPath("/atom.xml", pm.netExempt) {
		t.Error("/atom is shop-only; must not match on the global site")
	}
	if matchPath("/disabled", pm.netExempt) {
		t.Error("disabled row must not be compiled")
	}
	if matchPath("/other", pm.netExempt) {
		t.Error("/other must not be net-exempt")
	}

	// Separation from full bypass: a net-exempt feed must NOT land in the full
	// bypass matcher (else it would skip ja4 / honeypot / rate too).
	if matchPath("/feed.xml", pm.bypass) {
		t.Error("/feed is net-exempt only; it must NOT be in the full bypass matcher")
	}
	if !matchPath("/full-bypass", pm.bypass) {
		t.Error("/full-bypass belongs in the full bypass matcher")
	}

	// Per-site: on shop.example.com the /atom rule activates.
	pmShop := h.bypassMatchers(h.cfg(), "shop.example.com")
	if !matchPath("/atom.xml", pmShop.netExempt) {
		t.Error("/atom should be net-exempt on shop.example.com")
	}
}

// TestApplyNetExemptForm pins the ASN-tab save of net-exempt rows: ne_path /
// _title / _enabled / _site zip into BypassPath (Disabled = !enabled), and an
// invalid regex is rejected rather than silently stored.
func TestApplyNetExemptForm(t *testing.T) {
	form := url.Values{}
	form["ne_path"] = []string{"^/feed", "^/atom"}
	form["ne_title"] = []string{"RSS", ""}
	form["ne_site"] = []string{"", "shop.example.com"}
	form["ne_enabled"] = []string{"1", "0"} // row1 disabled
	form["ne_updated_at"] = []string{"0", "0"}
	r := httptest.NewRequest("POST", "/save?section=asn", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	var n settings.Nginx
	if err := applyNetExemptForm(&n, r, i18n.LangEN); err != nil {
		t.Fatalf("applyNetExemptForm: %v", err)
	}
	if len(n.NetExemptPaths.Paths) != 2 {
		t.Fatalf("want 2 rows, got %d (%+v)", len(n.NetExemptPaths.Paths), n.NetExemptPaths.Paths)
	}
	if p := n.NetExemptPaths.Paths[0]; p.Path != "^/feed" || p.Title != "RSS" || p.Disabled || p.Site != "" {
		t.Errorf("row0 = %+v, want ^/feed RSS enabled global", p)
	}
	if p := n.NetExemptPaths.Paths[1]; p.Path != "^/atom" || !p.Disabled || p.Site != "shop.example.com" {
		t.Errorf("row1 = %+v, want ^/atom disabled shop-only", p)
	}

	// An invalid regex is rejected (not silently stored).
	bad := url.Values{}
	bad["ne_path"] = []string{"("}
	br := httptest.NewRequest("POST", "/save", strings.NewReader(bad.Encode()))
	br.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = br.ParseForm()
	var n2 settings.Nginx
	if err := applyNetExemptForm(&n2, br, i18n.LangEN); err == nil {
		t.Error("invalid regex must be rejected")
	}
}
