package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

var (
	showCreditInputRE = regexp.MustCompile(`<input[^>]*id="branding-show-credit"[^>]*>`)
	testPagesInputRE  = regexp.MustCompile(`<input[^>]*name="public_test_pages"[^>]*>`)
	previewCreditRE   = regexp.MustCompile(`_preview_show_credit=([01])`)
)

func settingsPage(t *testing.T, h *Handler, tab, scope string) string {
	t.Helper()
	url := "/unmask/admin/settings/?tab=" + tab
	if scope != "" {
		url += "&scope=" + scope
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.SetPathValue("tab", tab)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("settings page tab=%s scope=%q: want 200, got %d", tab, scope, rr.Code)
	}
	return rr.Body.String()
}

func checkboxChecked(t *testing.T, body string, re *regexp.Regexp) bool {
	t.Helper()
	m := re.FindString(body)
	if m == "" {
		t.Fatalf("checkbox %v not found in page", re)
	}
	return strings.Contains(m, "checked")
}

// The *bool settings fields distinguish "off here" (pointer to false) from
// "inherit" (nil).  Go templates treat ANY non-nil pointer as true, so a
// checkbox rendered straight off the raw record shows "checked" for a site
// that explicitly turned the flag OFF -- the operator unchecks, saves, and the
// page answers with the box ticked again.  Worse than cosmetic: the lying form
// re-submits value=1 on the next unrelated save and silently turns the flag
// back on.  Seen in production on a per-site scope for show_credit.
//
// The checkbox must therefore render the RESOLVED value (site over Default),
// which is also what the challenge page actually serves.
func TestBoolCheckboxesRenderResolvedValue(t *testing.T) {
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	s.Branding.Default = settings.BrandingValues{ShowCredit: settings.BoolPtr(true)}
	s.Branding.Sites = map[string]settings.BrandingValues{
		"off.example.jp": {ShowCredit: settings.BoolPtr(false)},
		"inh.example.jp": {SiteName: "pinned-name-only"},
	}
	s.Challenge.Default.PublicTestPages = settings.BoolPtr(true)
	s.Challenge.Sites = map[string]settings.ChallengeValues{
		"off.example.jp": {PublicTestPages: settings.BoolPtr(false)},
	}
	h := siteSaveHandler(t, s)

	// The reported case: a site that pins the flag OFF under a default-ON
	// global must render unchecked.
	theme := settingsPage(t, h, "theme", "off.example.jp")
	if checkboxChecked(t, theme, showCreditInputRE) {
		t.Error("show_credit pinned false per-site renders checked (non-nil *bool treated as true)")
	}
	if m := previewCreditRE.FindStringSubmatch(theme); m != nil && m[1] != "0" {
		t.Error("theme preview iframe passes _preview_show_credit=1 for a site that turned the credit off")
	}
	if checkboxChecked(t, settingsPage(t, h, "challenge", "off.example.jp"), testPagesInputRE) {
		t.Error("public_test_pages pinned false per-site renders checked (same *bool class)")
	}

	// The guard for the naive fix (dereferencing the RAW record): a site
	// entry that does NOT set the flag inherits Default(true) and must render
	// checked -- otherwise an untouched save would pin it false.
	if !checkboxChecked(t, settingsPage(t, h, "theme", "inh.example.jp"), showCreditInputRE) {
		t.Error("show_credit inherited from a default-ON global renders unchecked -- an untouched save would silently pin it off")
	}

	// Default scope stays plain.
	if !checkboxChecked(t, settingsPage(t, h, "theme", ""), showCreditInputRE) {
		t.Error("show_credit ON at the default scope renders unchecked")
	}
}

// The theme tab's live preview iframes must point at the site-scoped
// challenge route when a per-site scope is being edited.  The plain
// /challenge/ route resolves branding by request host (= the admin's own
// hostname), so a per-site logo never appeared in the previews: a logo is
// fetched by the challenge page from its branding route and cannot ride a
// _preview_* query param the way the site name does.  The operator uploads,
// the thumbnail next to the field shows the file, and the five previews stay
// logo-less -- reading as "the save did not take".
func TestThemePreviewIframesUseSiteScopedRoute(t *testing.T) {
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	s.Branding.Sites = map[string]settings.BrandingValues{
		"off.example.jp": {SiteName: "Off"},
	}
	h := siteSaveHandler(t, s)

	site := settingsPage(t, h, "theme", "off.example.jp")
	if !strings.Contains(site, `/unmask/test/site/off.example.jp/?_test_ja4=0`) {
		t.Error("per-site scope: preview iframes still use the host-resolved /challenge/ route -- the site's logo cannot appear")
	}
	if strings.Contains(site, `/unmask/challenge/?_test_ja4=0`) {
		t.Error("per-site scope: some preview iframe still points at the plain route")
	}

	def := settingsPage(t, h, "theme", "")
	if !strings.Contains(def, `/unmask/challenge/?_test_ja4=0`) {
		t.Error("default scope: preview iframes must keep the plain host-resolved route")
	}
}

// The round trip the operator actually performs: uncheck on the per-site form,
// save, land back on the form.  The stored record must say false, and the page
// the redirect renders must show the box unchecked.
func TestShowCreditUncheckSaveRoundTrip(t *testing.T) {
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	s.Branding.Default = settings.BrandingValues{ShowCredit: settings.BoolPtr(true)}
	h := siteSaveHandler(t, s)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("site", "off.example.jp")
	_ = mw.WriteField("use_site_override", "1")
	_ = mw.WriteField("theme", "default")
	// show_credit deliberately absent = the checkbox was unchecked.
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost,
		"/unmask/admin/settings/branding/site/save?site=off.example.jp", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	h.AdminBrandingSiteSave(httptest.NewRecorder(), req)

	got := *h.cfg()
	bv, ok := got.Branding.Sites["off.example.jp"]
	if !ok {
		t.Fatal("per-site branding record was not created")
	}
	if bv.ShowCredit == nil || *bv.ShowCredit {
		t.Fatalf("stored ShowCredit = %v, want explicit false", bv.ShowCredit)
	}
	if got.Branding.Resolve("off.example.jp").IsShowCredit() {
		t.Error("resolved value still shows the credit after the uncheck-save")
	}

	// What the redirect renders.
	body := settingsPage(t, h, "theme", "off.example.jp")
	if checkboxChecked(t, body, showCreditInputRE) {
		t.Error("after saving with the box unchecked, the form answers with the box checked again")
	}
}
