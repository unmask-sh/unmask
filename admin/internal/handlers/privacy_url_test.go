package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The branding record's privacy_url reaches the page only as an address the
// page may link -- https:// or http://, or a path on this site -- and a form
// that posts the field is held to the same shape; one that does not post it
// leaves the value alone.
func TestPrivacyURLReachesThePageWhenLinkable(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://example.com/privacy", "https://example.com/privacy"},
		{"http://example.com/privacy?lang=ja", "http://example.com/privacy?lang=ja"},
		{"/privacy/", "/privacy/"},
		{"  https://example.com/p  ", "https://example.com/p"},
		{"javascript:alert(1)", ""},
		{"//evil.example/", ""},
		{"privacy", ""},
		{"https://example.com/p\"onclick=1", ""},
		{"", ""},
	} {
		if got := linkableURL(c.in); got != c.want {
			t.Errorf("linkableURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	b := settings.BrandingValues{PrivacyURL: "https://example.com/privacy", CopyPreset: settings.BrandingPresetFriendly}
	if got := brandingInjectJSON(b, "/unmask", "", false, ""); !strings.Contains(got, `"privacy_url":"https://example.com/privacy"`) {
		t.Errorf("the page does not get the address: %s", got)
	}
	b.PrivacyURL = "javascript:alert(1)"
	if got := brandingInjectJSON(b, "/unmask", "", false, ""); strings.Contains(got, "privacy_url") {
		t.Errorf("an address the page may not link reached it: %s", got)
	}

	post := func(form url.Values) (settings.BrandingValues, error) {
		t.Helper()
		r := httptest.NewRequest("POST", "/x?section=branding", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		cur := settings.BrandingValues{PrivacyURL: "https://example.com/kept"}
		err := applyBrandingForm(&cur, "default", r)
		return cur, err
	}
	// A page without the field leaves the configured value.
	if cur, err := post(url.Values{"branding_site_name": {"Acme"}}); err != nil || cur.PrivacyURL != "https://example.com/kept" {
		t.Errorf("a form without the field: %q, %v", cur.PrivacyURL, err)
	}
	if cur, err := post(url.Values{"branding_privacy_url": {"/privacy"}}); err != nil || cur.PrivacyURL != "/privacy" {
		t.Errorf("a form with the field: %q, %v", cur.PrivacyURL, err)
	}
	if cur, err := post(url.Values{"branding_privacy_url": {""}}); err != nil || cur.PrivacyURL != "" {
		t.Errorf("a form clearing the field: %q, %v", cur.PrivacyURL, err)
	}
	if _, err := post(url.Values{"branding_privacy_url": {"javascript:alert(1)"}}); err == nil {
		t.Error("an address the page may not link was accepted")
	}
}
