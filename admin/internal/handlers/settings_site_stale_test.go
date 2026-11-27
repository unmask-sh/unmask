package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A site's forms (the challenge and theme tabs at a site's scope) carry the
// version of the settings their page showed, as every other form of the
// settings does, and a save from a page opened before another save landed is
// merged three ways.  They carried none and their endpoints merged nothing:
// the form put every field it carries back to what its page showed, and a
// second tab's save of a site's record undid the first one's without a word.

// siteSave posts vals to a site's save or delete endpoint and returns where
// the answer sends the browser.
func (e *siteEnv) siteSave(handler func(http.ResponseWriter, *http.Request), action string, vals url.Values) string {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodPost, action, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusFound {
		e.t.Fatalf("POST %s: %d %s", action, rr.Code, rr.Body.String())
	}
	return rr.Header().Get("Location")
}

// withSiteRecord: a site that has a record of its own, so that its forms are
// shown with the override on.
func withSiteRecord(t *testing.T) *siteEnv {
	e := newSiteEnv(t, nil)
	s := e.load()
	s.Challenge.Sites = map[string]settings.ChallengeValues{formSite: {PowDifficulty: 20}}
	s.Branding.Sites = map[string]settings.BrandingValues{formSite: {SiteName: "Shop"}}
	e.store(s)
	return e
}

func TestSiteChallengeFormFromAnOlderTabIsMerged(t *testing.T) {
	e := withSiteRecord(t)
	if !strings.Contains(e.page("challenge"), `name="_base"`) {
		t.Fatal("the site's challenge form carries no _base")
	}
	tabA := e.form("challenge") // opened now, saved last
	valsA := siteFormValues(tabA, false)

	// Another tab: the daemon stops compressing this site's page, and puts
	// the script inside it.
	tabB := e.form("challenge")
	valsB := siteFormValues(tabB, false)
	valsB.Del("challenge_page_gzip")
	valsB.Set("challenge_js_inline", "1")
	e.post("challenge", tabB, valsB)

	// The first tab, still showing the earlier state, changes another field.
	valsA.Set("pow_difficulty", "22")
	e.post("challenge", tabA, valsA)

	got := e.load().Challenge.Sites[formSite]
	if got.PowDifficulty != 22 {
		t.Errorf("the older tab's own change did not land: difficulty %d, want 22", got.PowDifficulty)
	}
	if got.ChallengePageGzip == nil || *got.ChallengePageGzip || got.ChallengeJSInline == nil || !*got.ChallengeJSInline {
		t.Errorf("the older tab's save undid the other tab's: page_gzip=%v js_inline=%v, want false and true",
			got.ChallengePageGzip, got.ChallengeJSInline)
	}
}

func TestSiteThemeFormFromAnOlderTabIsMerged(t *testing.T) {
	e := withSiteRecord(t)
	if !strings.Contains(e.page("theme"), `name="_base"`) {
		t.Fatal("the site's theme form carries no _base")
	}
	tabA := e.form("theme")
	valsA := siteFormValues(tabA, false)

	tabB := e.form("theme")
	valsB := siteFormValues(tabB, false)
	valsB.Set("branding_footer_text", "Operated by the other tab")
	e.post("theme", tabB, valsB)

	valsA.Set("branding_site_name", "Shop, renamed")
	e.post("theme", tabA, valsA)

	got := e.load().Branding.Sites[formSite]
	if got.SiteName != "Shop, renamed" || got.FooterText != "Operated by the other tab" {
		t.Errorf("after both saves the site's record says name %q and footer %q; want the older tab's name and the other tab's footer",
			got.SiteName, got.FooterText)
	}
}

// Both tabs changed the same setting, differently: the later save is
// refused, and the settings stay as the first save left them.  So is a save
// from a page whose version the daemon no longer keeps (a restart since).
func TestSiteFormConflictIsRefused(t *testing.T) {
	e := withSiteRecord(t)
	tabA := e.form("challenge")
	valsA := siteFormValues(tabA, false)

	tabB := e.form("challenge")
	valsB := siteFormValues(tabB, false)
	valsB.Set("pow_difficulty", "21")
	e.post("challenge", tabB, valsB)

	valsA.Set("pow_difficulty", "22")
	if loc := e.siteSave(e.h.AdminChallengeSiteSave, tabA.action, valsA); strings.Contains(loc, "saved=1") {
		t.Errorf("a save that conflicts with the other tab's was taken: %s", loc)
	}
	if got := e.load().Challenge.Sites[formSite].PowDifficulty; got != 21 {
		t.Errorf("after the refused save the difficulty is %d, want the first save's 21", got)
	}

	// A version the daemon does not know: the page is to be opened again.
	tabC := e.form("challenge")
	valsC := siteFormValues(tabC, false)
	valsC.Set("_base", "0000000000000000")
	valsC.Set("pow_difficulty", "23")
	if loc := e.siteSave(e.h.AdminChallengeSiteSave, tabC.action, valsC); strings.Contains(loc, "saved=1") {
		t.Errorf("a save from a page of an unknown version was taken: %s", loc)
	}
	if got := e.load().Challenge.Sites[formSite].PowDifficulty; got != 21 {
		t.Errorf("after the refused save the difficulty is %d, want 21", got)
	}
}

// A delete drops the site's record whole, from an older tab too: there is
// nothing of it to merge, and it touches nothing else.
func TestSiteDeleteFromAnOlderTabDropsTheRecord(t *testing.T) {
	e := withSiteRecord(t)
	tabA := e.form("challenge")
	valsA := siteFormValues(tabA, false)

	tabB := e.form("challenge")
	valsB := siteFormValues(tabB, false)
	valsB.Set("pow_difficulty", "21")
	e.post("challenge", tabB, valsB)
	// And a change elsewhere in the settings, which the delete leaves alone.
	e.setDefault(func(s *settings.Settings) { s.Challenge.Default.PowDifficulty = 19 })

	action := strings.Replace(tabA.action, "/site/save", "/site/delete", 1)
	if loc := e.siteSave(e.h.AdminChallengeSiteDelete, action, valsA); !strings.Contains(loc, "saved=1") {
		t.Fatalf("the delete from the older tab was refused: %s", loc)
	}
	s := e.load()
	if _, ok := s.Challenge.Sites[formSite]; ok {
		t.Errorf("the site's record is still there after the delete: %+v", s.Challenge.Sites[formSite])
	}
	if s.Challenge.Default.PowDifficulty != 19 {
		t.Errorf("the delete changed Default's difficulty to %d", s.Challenge.Default.PowDifficulty)
	}
}
