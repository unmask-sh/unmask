package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The test-page site picker resolves another site's VALUES only for callers
// that are allowed to preview arbitrary sites: an admin session, or a host
// whose operator opted in to the public picker.  Everyone else must keep the
// host-derived site, or a visitor could pick a weaker site's CAPTCHA provider
// / difficulty for the host they are actually passing.

func pickerSettings(h *Handler) settings.Settings {
	s := *h.cfg()
	s.Challenge.Sites = map[string]settings.ChallengeValues{
		"shop.example.jp": {PowDifficulty: 9, CaptchaProvider: settings.Captcha{Provider: "turnstile", TurnstileSiteKey: "0xSITEKEY"}},
	}
	s.Branding.Sites = map[string]settings.BrandingValues{
		"shop.example.jp": {LogoPath: "/tmp/shop-logo.png", SiteName: "Shop"},
	}
	return s
}

func TestTestSiteOverrideGate(t *testing.T) {
	h := newTestHandler(t)
	h.SetSettings(pickerSettings(h))

	// No {site} path value: never an override.
	r := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	if _, ok := h.testSiteOverride(r); ok {
		t.Fatal("override granted without a {site} path value")
	}

	// {site} present but caller is neither admin nor opted-in public: refuse.
	r = httptest.NewRequest("GET", "/unmask/test/site/shop.example.jp/", nil)
	r.SetPathValue("site", "shop.example.jp")
	if _, ok := h.testSiteOverride(r); ok {
		t.Fatal("override granted to an unauthorized visitor")
	}

	// Public pages ON alone is not enough -- the picker flag is a separate opt-in.
	s := pickerSettings(h)
	s.Challenge.Default.PublicTestPages = settings.BoolPtr(true)
	h.SetSettings(s)
	if _, ok := h.testSiteOverride(r); ok {
		t.Fatal("override granted with public_test_pages only (picker flag off)")
	}

	// Public pages ON + picker opt-in: granted.
	s.Challenge.Default.PublicTestPagesSitePicker = settings.BoolPtr(true)
	h.SetSettings(s)
	if got, ok := h.testSiteOverride(r); !ok || got != "shop.example.jp" {
		t.Fatalf("public picker: want (shop.example.jp,true), got (%q,%v)", got, ok)
	}

	// Admin session: granted regardless of the public flags.
	h.SetSettings(pickerSettings(h))
	c := issueSessionCookie(h.cfg().Secret.BVSecret, 1, "admin", false, false)
	r.AddCookie(c)
	if got, ok := h.testSiteOverride(r); !ok || got != "shop.example.jp" {
		t.Fatalf("admin session: want (shop.example.jp,true), got (%q,%v)", got, ok)
	}

	// Invalid site shapes are refused even for an admin.
	for _, bad := range []string{"UPPER.example.jp", "a b", "-lead.dash", "trail.dash-", strings.Repeat("a", 300)} {
		rb := httptest.NewRequest("GET", "/unmask/test/site/x/", nil)
		rb.SetPathValue("site", bad)
		rb.AddCookie(c)
		if _, ok := h.testSiteOverride(rb); ok {
			t.Errorf("override granted for invalid site %q", bad)
		}
	}
}

func TestTestIndexSitePickerRendering(t *testing.T) {
	h := newTestHandler(t)

	serve := func(path string) string {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.TestIndex(w, r)
		return w.Body.String()
	}

	// Admin side, but no site has its own settings: nothing to pick.
	if body := serve("/unmask/admin/test/"); strings.Contains(body, `id="site-picker"`) {
		t.Fatal("picker rendered with no per-site settings")
	}

	h.SetSettings(pickerSettings(h))

	// Admin side with per-site settings: picker always renders.
	body := serve("/unmask/admin/test/")
	if !strings.Contains(body, `id="site-picker"`) || !strings.Contains(body, "shop.example.jp") {
		t.Fatal("admin test index misses the site picker / site entry")
	}
	// The force links must expose their kind for the picker JS rewrite.
	if !strings.Contains(body, `data-force="pow"`) || !strings.Contains(body, `data-force="captcha"`) {
		t.Fatal("force links miss data-force attributes")
	}

	// Public side without the opt-in: no picker.
	if body := serve("/unmask/test/"); strings.Contains(body, `id="site-picker"`) {
		t.Fatal("public test index rendered the picker without the opt-in")
	}

	// Public side with the opt-in: picker renders.
	s := pickerSettings(h)
	s.Challenge.Default.PublicTestPages = settings.BoolPtr(true)
	s.Challenge.Default.PublicTestPagesSitePicker = settings.BoolPtr(true)
	h.SetSettings(s)
	if body := serve("/unmask/test/"); !strings.Contains(body, `id="site-picker"`) {
		t.Fatal("public test index misses the picker despite the opt-in")
	}
}

// ServeChallenge must render the OVERRIDDEN site's values (here: its PoW
// difficulty embed) for an authorized caller, and the host-derived values for
// everyone else hitting the same site-scoped URL.
func TestServeChallengeSiteOverrideValues(t *testing.T) {
	h := newTestHandler(t)
	s := pickerSettings(h)
	// Both inside ResolvedPowDifficulty's accepted 8-24 band (out-of-band
	// values fall back to the hard default and would blur the assertion).
	s.Challenge.Default.PowDifficulty = 10
	h.SetSettings(s)

	serve := func(withSession bool) string {
		t.Helper()
		r := httptest.NewRequest("GET", "/unmask/test/site/shop.example.jp/", nil)
		r.Header.Set("User-Agent", uaCurrentChrome)
		r.SetPathValue("site", "shop.example.jp")
		if withSession {
			r.AddCookie(issueSessionCookie(h.cfg().Secret.BVSecret, 1, "admin", false, false))
		}
		w := httptest.NewRecorder()
		h.ServeChallenge(w, r)
		return w.Body.String()
	}

	// The site preview overrides the site's VISIBLE knobs but NOT the PoW
	// difficulty: the _bv it yields is verified at the physical host after the
	// redirect (native module / fa-check), which resolve the HOST's difficulty
	// — a lower previewed difficulty produced a PoW that verifier rejected, so
	// the visitor looped.  Both authorized and unauthorized callers get the
	// host difficulty (10); the CAPTCHA provider and logo DO follow the site.
	authed := serve(true)
	if !strings.Contains(authed, "/*__POW_DIFFICULTY__*/10") {
		t.Fatal("authorized preview must keep the HOST's PoW difficulty (else the solved _bv loops)")
	}
	if strings.Contains(authed, "/*__POW_DIFFICULTY__*/9") {
		t.Fatal("authorized preview must NOT embed the previewed site's lower difficulty")
	}
	if !strings.Contains(authed, `"provider":"turnstile"`) {
		t.Fatal("authorized preview must use the previewed site's CAPTCHA provider")
	}
	if !strings.Contains(authed, "/branding/shop.example.jp/logo") {
		t.Fatal("authorized preview must point the logo at the site-scoped route")
	}
	if body := serve(false); !strings.Contains(body, "/*__POW_DIFFICULTY__*/10") {
		t.Fatal("unauthorized caller must keep the host-derived difficulty")
	}
}

// The site-scoped logo route serves the previewed site's logo for an
// authorized caller and the host's for everyone else — the branding parallel
// to the challenge/verify override.
func TestServeBrandingLogoSiteScoped(t *testing.T) {
	dir := t.TempDir()
	shopLogo := dir + "/shop.png"
	if err := os.WriteFile(shopLogo, []byte("\x89PNG\r\n\x1a\nshop"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newTestHandler(t)
	s := *h.cfg()
	s.Branding.Sites = map[string]settings.BrandingValues{
		"shop.example.jp": {LogoPath: shopLogo},
	}
	h.SetSettings(s)

	get := func(withSession bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/unmask/branding/shop.example.jp/logo", nil)
		r.SetPathValue("site", "shop.example.jp")
		if withSession {
			r.AddCookie(issueSessionCookie(h.cfg().Secret.BVSecret, 1, "admin", false, false))
		}
		w := httptest.NewRecorder()
		h.ServeBrandingLogo(w, r)
		return w
	}
	// Authorized: the shop logo bytes come back.
	if w := get(true); w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Fatalf("authorized site-scoped logo: want 200 with bytes, got %d len=%d", w.Code, w.Body.Len())
	}
	// Unauthorized: falls back to the host (no host logo here) -> 404, never
	// the shop bytes.
	if w := get(false); w.Code != http.StatusNotFound {
		t.Fatalf("unauthorized site-scoped logo: want 404 (host has no logo), got %d", w.Code)
	}
}

// The challenge-tab form must round-trip the new opt-in with the hidden-marker
// pattern (absent marker = leave the stored value untouched).
func TestApplyChallengeFormSitePicker(t *testing.T) {
	mkReq := func(vals url.Values) *settings.ChallengeValues {
		t.Helper()
		r := httptest.NewRequest("POST", "/unmask/admin/settings/save?section=challenge", strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c := &settings.ChallengeValues{PublicTestPagesSitePicker: settings.BoolPtr(true)}
		if err := applyChallengeForm(c, r); err != nil {
			t.Fatalf("applyChallengeForm: %v", err)
		}
		return c
	}

	// Marker present + unchecked: stored true flips to false.
	c := mkReq(url.Values{"public_test_pages_site_picker_present": {"1"}})
	if c.IsPublicTestPagesSitePicker() {
		t.Fatal("unchecked box (marker present) must clear the flag")
	}
	// Marker present + checked: set.
	c = mkReq(url.Values{
		"public_test_pages_site_picker_present": {"1"},
		"public_test_pages_site_picker":         {"1"},
	})
	if !c.IsPublicTestPagesSitePicker() {
		t.Fatal("checked box must set the flag")
	}
	// Marker absent (a form that predates the field): leave untouched.
	c = mkReq(url.Values{})
	if !c.IsPublicTestPagesSitePicker() {
		t.Fatal("absent marker must not touch the stored value")
	}
}
