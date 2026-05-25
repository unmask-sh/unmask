package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestBrandingOverrideFieldCount: the picker badge "(N overrides)" reads
// directly from this helper.  Each non-empty top-level field counts once;
// nested Overrides on an override entry is ignored (it should not exist
// but the helper must be safe even when one slips in).
func TestBrandingOverrideFieldCount(t *testing.T) {
	cases := []struct {
		name string
		b    settings.Branding
		want int
	}{
		{"empty -> 0", settings.Branding{}, 0},
		{"site_name only -> 1", settings.Branding{SiteName: "Shop"}, 1},
		{"all four -> 4", settings.Branding{
			SiteName: "Shop", FooterText: "Operated by Shop",
			CopyPreset: "minimal", LogoPath: "/etc/x.svg",
		}, 4},
		{"whitespace-only -> 0", settings.Branding{
			SiteName: "  ", FooterText: "\t",
		}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := brandingOverrideFieldCount(tc.b); got != tc.want {
				t.Errorf("brandingOverrideFieldCount(%+v) = %d, want %d", tc.b, got, tc.want)
			}
		})
	}
}

// TestResolveSettingsScope: cookie wins by default, query string overrides
// the cookie (= deep-link "?scope=default" should always reset to baseline),
// and "default" / "" both map to the empty (= baseline) scope.
func TestResolveSettingsScope(t *testing.T) {
	cases := []struct {
		name   string
		cookie string
		query  string
		want   string
	}{
		{"nothing -> default", "", "", ""},
		{"cookie site", "shop.example.com", "", "shop.example.com"},
		{"cookie default -> baseline", "default", "", ""},
		{"query overrides cookie", "shop.example.com", "blog.example.com", "blog.example.com"},
		{"query default resets", "shop.example.com", "default", ""},
		{"whitespace -> baseline", "   ", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/admin/settings/"
			if tc.query != "" {
				url += "?scope=" + tc.query
			}
			r := httptest.NewRequest("GET", url, nil)
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: scopeCookieName, Value: tc.cookie})
			}
			if got := resolveSettingsScope(r); got != tc.want {
				t.Errorf("resolveSettingsScope cookie=%q query=%q = %q, want %q",
					tc.cookie, tc.query, got, tc.want)
			}
		})
	}
}

// brandingFormReq: helper to build a multipart form POST aimed at the
// branding save handler.  Only sets the text fields the test cares about;
// missing fields are left blank, matching how a real browser would submit
// an unchanged input.
func brandingFormReq(t *testing.T, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range fields {
		fw, err := w.CreateFormField(k)
		if err != nil {
			t.Fatalf("multipart field: %v", err)
		}
		if _, err := fw.Write([]byte(v)); err != nil {
			t.Fatalf("multipart write: %v", err)
		}
	}
	w.Close()
	r := httptest.NewRequest("POST", "/admin/settings/save?section=branding", &body)
	r.Header.Set("Content-Type", w.FormDataContentType())
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return r
}

// TestApplyBrandingFormScopedDefault: the empty-scope path delegates to the
// existing applyBrandingForm and writes directly into the top-level fields.
// Overrides map is left untouched.
func TestApplyBrandingFormScopedDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	cur := settings.Branding{
		SiteName: "MyCo",
		Overrides: map[string]settings.Branding{
			"shop.example.com": {SiteName: "Shop"},
		},
	}
	r := brandingFormReq(t, map[string]string{
		"branding_site_name":   "NewCo",
		"branding_footer_text": "Operated by NewCo",
		"branding_copy_preset": "minimal",
	})
	if err := applyBrandingFormScoped(&cur, cfg, r, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cur.SiteName != "NewCo" {
		t.Errorf("default scope did not write SiteName: got %q", cur.SiteName)
	}
	if cur.CopyPreset != "minimal" {
		t.Errorf("default scope did not write CopyPreset: got %q", cur.CopyPreset)
	}
	if _, ok := cur.Overrides["shop.example.com"]; !ok {
		t.Errorf("default scope must not touch existing overrides; got map %+v", cur.Overrides)
	}
}

// TestApplyBrandingFormScopedSiteCreate: site scope creates an override
// entry containing only the fields the operator filled in.  Empty fields
// stay out of the override (= inherit default) instead of writing empty
// strings that would shadow the default.
func TestApplyBrandingFormScopedSiteCreate(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	cur := settings.Branding{SiteName: "MyCo"}
	r := brandingFormReq(t, map[string]string{
		"branding_site_name":   "Shop",
		"branding_footer_text": "",      // blank -> inherit
		"branding_copy_preset": "minimal",
	})
	if err := applyBrandingFormScoped(&cur, cfg, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cur.SiteName != "MyCo" {
		t.Errorf("site scope must not touch default SiteName; got %q", cur.SiteName)
	}
	ov, ok := cur.Overrides["shop.example.com"]
	if !ok {
		t.Fatalf("override entry not created")
	}
	if ov.SiteName != "Shop" {
		t.Errorf("override SiteName = %q, want %q", ov.SiteName, "Shop")
	}
	if ov.FooterText != "" {
		t.Errorf("blank FooterText must inherit (= stay empty); got %q", ov.FooterText)
	}
	if ov.CopyPreset != "minimal" {
		t.Errorf("override CopyPreset = %q, want %q", ov.CopyPreset, "minimal")
	}
}

// TestApplyBrandingFormScopedSiteAllBlankDrops: every field blank + no logo
// + no clear → the site's override entry is dropped entirely so the YAML
// does not accumulate empty `{}` leftovers.
func TestApplyBrandingFormScopedSiteAllBlankDrops(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	cur := settings.Branding{
		SiteName: "MyCo",
		Overrides: map[string]settings.Branding{
			"shop.example.com": {SiteName: "Shop"},
		},
	}
	r := brandingFormReq(t, map[string]string{
		"branding_site_name":   "",
		"branding_footer_text": "",
		"branding_copy_preset": "default", // sentinel "inherit"
	})
	if err := applyBrandingFormScoped(&cur, cfg, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := cur.Overrides["shop.example.com"]; ok {
		t.Errorf("all-blank override should be deleted; map=%+v", cur.Overrides)
	}
}

// TestApplyBrandingFormScopedReset: branding_reset=1 wipes the site's
// override entry regardless of the rest of the form payload.  Default
// scope is unaffected.
func TestApplyBrandingFormScopedReset(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	cur := settings.Branding{
		SiteName: "MyCo",
		Overrides: map[string]settings.Branding{
			"shop.example.com": {SiteName: "Shop", CopyPreset: "minimal"},
			"blog.example.com": {CopyPreset: "neutral"},
		},
	}
	r := brandingFormReq(t, map[string]string{
		"branding_site_name": "ShouldBeIgnored",
		"branding_reset":     "1",
	})
	if err := applyBrandingFormScoped(&cur, cfg, r, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := cur.Overrides["shop.example.com"]; ok {
		t.Errorf("reset must drop the site entry; map=%+v", cur.Overrides)
	}
	if _, ok := cur.Overrides["blog.example.com"]; !ok {
		t.Errorf("reset must not touch sibling overrides; map=%+v", cur.Overrides)
	}
	if cur.SiteName != "MyCo" {
		t.Errorf("reset must not touch default SiteName; got %q", cur.SiteName)
	}
}

// TestOverrideSiteSafe: filesystem guard accepts Host-like strings, rejects
// path separators / dot-only / uppercase / control characters.  Lower-casing
// is the caller's job (resolveSettingsScope does it).
func TestOverrideSiteSafe(t *testing.T) {
	good := []string{"shop.example.com", "blog-1.example.com", "api2", "a", "h_1", "shop.example.com:8080"}
	bad := []string{"", ".", "..", "/abs", "../", "shop/x", "Shop.Example.com", "with space", "a;b"}
	for _, s := range good {
		if !overrideSiteSafe(s) {
			t.Errorf("overrideSiteSafe(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if overrideSiteSafe(s) {
			t.Errorf("overrideSiteSafe(%q) = true, want false", s)
		}
	}
}

// TestBuildScopeOptions_DefaultFirst: the picker always starts with the
// "default" pseudo-entry followed by sites in stable alphabetical order.
// Sites with overrides that no longer appear in the picker source remain
// listed so the operator can still reset them.
func TestBuildScopeOptions_DefaultFirst(t *testing.T) {
	h := &Handler{
		Settings: settings.Settings{
			Sites: settings.SiteAcceptanceConfig{
				Mode:    settings.SiteModeDefined,
				Defined: []string{"shop.example.com", "blog.example.com"},
			},
			Branding: settings.Branding{
				Overrides: map[string]settings.Branding{
					"shop.example.com": {SiteName: "Shop"},
					"ghost.example.com": {CopyPreset: "minimal"}, // stale override
				},
			},
		},
	}
	r := httptest.NewRequest("GET", "/admin/settings/", nil)
	opts := h.buildScopeOptions(r, "")
	if len(opts) == 0 || !opts[0].IsDefault {
		t.Fatalf("first option must be default; got %+v", opts)
	}
	var names []string
	for _, o := range opts[1:] {
		names = append(names, o.Site)
	}
	want := []string{"blog.example.com", "ghost.example.com", "shop.example.com"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("site order = %v, want %v", names, want)
	}
	// override count is wired from Branding.Overrides
	for _, o := range opts {
		if o.Site == "shop.example.com" && o.OverrideCount != 1 {
			t.Errorf("shop override count = %d, want 1", o.OverrideCount)
		}
		if o.Site == "blog.example.com" && o.OverrideCount != 0 {
			t.Errorf("blog override count = %d, want 0 (no overrides yet)", o.OverrideCount)
		}
	}
}
