package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// settingsSave posts one section of the main settings form.
func settingsSave(t *testing.T, h *Handler, section string, form url.Values) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section="+section, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	return rr.Result()
}

// challengeSiteSave posts the challenge tab's per-site form for a host.
func challengeSiteSave(t *testing.T, h *Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/challenge/site/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminChallengeSiteSave(rr, req)
	return rr
}

// A per-site PoW difficulty is rendered (http.inc's host map of
// $unmask_pow_difficulty, which the module verifies against), so the
// per-site save renders and asks for a reload like the main save.  It did
// neither: the daemon served the new difficulty at once while nginx kept
// verifying the old one, and a lower difficulty sent every solve back to
// the challenge -- with no render, a reload did not help either.
func TestSiteChallengeSaveRendersTheDifficulty(t *testing.T) {
	h := ruleTestHandler(t)
	if res := settingsSave(t, h, "about", url.Values{"version_check": {"1"}, "feed_sync": {"1"}}); res.StatusCode != http.StatusFound {
		t.Fatalf("first save: %d", res.StatusCode)
	}
	httpInc := filepath.Join(h.cfg().Nginx.OutputDir, "http.inc")
	if _, err := os.Stat(httpInc); err != nil {
		t.Fatalf("no http.inc after the first save: %v", err)
	}

	rr := challengeSiteSave(t, h, url.Values{
		"site":                    {"shop.example.com"},
		"use_site_override":       {"1"},
		"pow_difficulty":          {"10"},
		"challenge_display_style": {"visible"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("site save: %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "saved=1") || !strings.Contains(loc, "reload=1") {
		t.Errorf("the redirect does not ask for a reload: %s", loc)
	}
	b, err := os.ReadFile(httpInc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"shop.example.com" 10;`) {
		t.Errorf("http.inc does not carry the site's difficulty")
	}

	// A save that changes nothing nginx reads asks for no reload.
	rr = challengeSiteSave(t, h, url.Values{
		"site":                    {"shop.example.com"},
		"use_site_override":       {"1"},
		"pow_difficulty":          {"10"},
		"challenge_display_style": {"visible"},
	})
	if loc := rr.Header().Get("Location"); strings.Contains(loc, "reload=1") {
		t.Errorf("an unchanged save asks for a reload: %s", loc)
	}
}

// The per-site challenge form carries no CAPTCHA provider fields (they are
// on the captcha tab), so saving it leaves the site's provider alone.  It
// read the absent provider as "builtin" and switched the site off Turnstile.
func TestSiteChallengeSaveKeepsTheCaptchaProvider(t *testing.T) {
	h := ruleTestHandler(t)
	if res := settingsSave(t, h, "captcha", url.Values{
		"provider": {"turnstile"}, "turnstile_site_key": {"0x4AAA-site"}, "turnstile_secret_key": {"0x4AAA-secret"},
	}); res.StatusCode != http.StatusFound {
		t.Fatalf("captcha save: %d", res.StatusCode)
	}
	// Exactly the fields the challenge tab's per-site form posts.
	rr := challengeSiteSave(t, h, url.Values{
		"site":                                  {"shop.example.com"},
		"use_site_override":                     {"1"},
		"pow_cookie_valid_seconds":              {"86400"},
		"captcha_cookie_valid_seconds":          {"1209600"},
		"pow_difficulty":                        {""},
		"challenge_display_style":               {"visible"},
		"public_test_pages_present":             {"1"},
		"public_test_pages_site_picker_present": {"1"},
		"public_test_pages_site_picker":         {"1"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("site save: %d", rr.Code)
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	got := cur.Challenge.Resolve("shop.example.com").CaptchaProvider
	if got.Provider != "turnstile" || got.TurnstileSiteKey != "0x4AAA-site" {
		t.Fatalf("the site's CAPTCHA after a per-site save: provider=%q site_key=%q, want turnstile / 0x4AAA-site", got.Provider, got.TurnstileSiteKey)
	}
}
