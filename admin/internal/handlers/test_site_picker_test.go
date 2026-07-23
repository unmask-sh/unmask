package handlers

import (
	"net/http/httptest"
	"net/url"
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
		"shop.example.jp": {PowDifficulty: 9},
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
	r = httptest.NewRequest("GET", "/unmask/challenge/shop.example.jp/", nil)
	r.SetPathValue("site", "shop.example.jp")
	if _, ok := h.testSiteOverride(r); ok {
		t.Fatal("override granted to an unauthorized visitor")
	}

	// Public pages ON alone is not enough -- the picker flag is a separate opt-in.
	s := pickerSettings(h)
	s.Challenge.Default.PublicTestPages = true
	h.SetSettings(s)
	if _, ok := h.testSiteOverride(r); ok {
		t.Fatal("override granted with public_test_pages only (picker flag off)")
	}

	// Public pages ON + picker opt-in: granted.
	s.Challenge.Default.PublicTestPagesSitePicker = true
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
		rb := httptest.NewRequest("GET", "/unmask/challenge/x/", nil)
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
	s.Challenge.Default.PublicTestPages = true
	s.Challenge.Default.PublicTestPagesSitePicker = true
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
		r := httptest.NewRequest("GET", "/unmask/challenge/shop.example.jp/", nil)
		r.Header.Set("User-Agent", uaCurrentChrome)
		r.SetPathValue("site", "shop.example.jp")
		if withSession {
			r.AddCookie(issueSessionCookie(h.cfg().Secret.BVSecret, 1, "admin", false, false))
		}
		w := httptest.NewRecorder()
		h.ServeChallenge(w, r)
		return w.Body.String()
	}

	if body := serve(true); !strings.Contains(body, "/*__POW_DIFFICULTY__*/9") {
		t.Fatal("authorized caller did not get the overridden site's difficulty")
	}
	if body := serve(false); !strings.Contains(body, "/*__POW_DIFFICULTY__*/10") {
		t.Fatal("unauthorized caller must keep the host-derived difficulty")
	}
}

// The challenge-tab form must round-trip the new opt-in with the hidden-marker
// pattern (absent marker = leave the stored value untouched).
func TestApplyChallengeFormSitePicker(t *testing.T) {
	mkReq := func(vals url.Values) *settings.ChallengeValues {
		t.Helper()
		r := httptest.NewRequest("POST", "/unmask/admin/settings/save?section=challenge", strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c := &settings.ChallengeValues{PublicTestPagesSitePicker: true}
		if err := applyChallengeForm(c, r); err != nil {
			t.Fatalf("applyChallengeForm: %v", err)
		}
		return c
	}

	// Marker present + unchecked: stored true flips to false.
	c := mkReq(url.Values{"public_test_pages_site_picker_present": {"1"}})
	if c.PublicTestPagesSitePicker {
		t.Fatal("unchecked box (marker present) must clear the flag")
	}
	// Marker present + checked: set.
	c = mkReq(url.Values{
		"public_test_pages_site_picker_present": {"1"},
		"public_test_pages_site_picker":         {"1"},
	})
	if !c.PublicTestPagesSitePicker {
		t.Fatal("checked box must set the flag")
	}
	// Marker absent (a form that predates the field): leave untouched.
	c = mkReq(url.Values{})
	if !c.PublicTestPagesSitePicker {
		t.Fatal("absent marker must not touch the stored value")
	}
}
