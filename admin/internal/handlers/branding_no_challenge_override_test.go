package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// siteSaveHandler backs the per-site save endpoints with a real config file --
// adminScalarSiteSave persists through settings.Save, so without one it rejects
// the request outright.
func siteSaveHandler(t *testing.T, s settings.Settings) *Handler {
	t.Helper()
	h := newTestHandler(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)
	return h
}

// TestBrandingSiteSaveLeavesChallengeAlone: picking a theme for one site used
// to mint a complete challenge-behaviour override for it, because the theme
// lived on ChallengeValues and a challenge record is inherited whole or owned
// whole -- so storing a theme meant storing a snapshot of everything else too.
// The operator saw a site they had only styled listed as having challenge
// overrides, and the snapshot then stopped tracking Default: a later change to
// the PoW difficulty silently skipped every site that had ever been styled.
//
// Design custom + challenge inherited is an ordinary combination, and after the
// move it is representable.
func TestBrandingSiteSaveLeavesChallengeAlone(t *testing.T) {
	var base settings.Settings
	base.Challenge.Default.PowDifficulty = 18
	h := siteSaveHandler(t, base)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("site", "shop.example.com")
	_ = mw.WriteField("use_site_override", "1")
	_ = mw.WriteField("branding_site_name", "Shop")
	_ = mw.WriteField("theme", "terminal")
	_ = mw.WriteField("show_credit", "1")
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost,
		"/unmask/admin/settings/branding/site/save?site=shop.example.com", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	h.AdminBrandingSiteSave(rr, req)

	got := *h.cfg()
	// The appearance landed.
	bv, ok := got.Branding.Sites["shop.example.com"]
	if !ok {
		t.Fatalf("no branding record was written (status %d)", rr.Code)
	}
	if bv.Theme != "terminal" || !bv.IsShowCredit() {
		t.Errorf("branding record = theme %q credit %v, want terminal/true", bv.Theme, bv.IsShowCredit())
	}
	// And nothing was written to the challenge side.  This is the whole point.
	if _, leaked := got.Challenge.Sites["shop.example.com"]; leaked {
		t.Error("styling a site created a challenge override for it")
	}

	// The site therefore still tracks Default: raising the global difficulty
	// reaches it, which a snapshot would have blocked.
	cfg2 := got
	cfg2.Challenge.Default.PowDifficulty = 22
	h.SetSettings(cfg2)
	if d := h.cfg().Challenge.Resolve("shop.example.com").PowDifficulty; d != 22 {
		t.Errorf("styled site resolved difficulty %d, want the new Default 22", d)
	}
}

// TestChallengeSiteSaveIgnoresTheme: the challenge tab's form shares field
// names with the theme tab, so it used to read `theme` too.  Now that the theme
// belongs to the branding record, reading it here would write appearance into
// the behaviour record again through the other door.
func TestChallengeSiteSaveIgnoresTheme(t *testing.T) {
	var base settings.Settings
	base.Branding.Sites = map[string]settings.BrandingValues{
		"shop.example.com": {Theme: "paper"},
	}
	h := siteSaveHandler(t, base)

	form := url.Values{
		"site":              {"shop.example.com"},
		"use_site_override": {"1"},
		"pow_difficulty":    {"22"},
		"theme":             {"terminal"}, // present in the payload, must be ignored
	}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/challenge/site/save",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.AdminChallengeSiteSave(httptest.NewRecorder(), req)

	got := *h.cfg()
	if d := got.Challenge.Sites["shop.example.com"].PowDifficulty; d != 22 {
		t.Errorf("the field this form owns did not save: difficulty=%d", d)
	}
	if th := got.Branding.Sites["shop.example.com"].Theme; th != "paper" {
		t.Errorf("branding theme = %q, want the challenge form to have left it at paper", th)
	}
}
