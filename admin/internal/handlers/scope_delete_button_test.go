package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// deleteButtonFor returns the rendered delete button for the named tab, or ""
// when the page did not offer one.
func deleteButtonFor(body, tab string) string {
	re := regexp.MustCompile(`(?s)<button type="submit" class="scope-delete".*?</button>`)
	for _, b := range re.FindAllString(body, -1) {
		if strings.Contains(b, "/admin/settings/"+tab+"/site/delete") {
			return b
		}
	}
	return ""
}

func deleteTestHandler(t *testing.T, s settings.Settings) *Handler {
	t.Helper()
	h := newTestHandler(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	s.Server.BasePath = "/unmask"
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)
	return h
}

// TestScopeDeleteButtonRendered: the per-site delete endpoints have existed,
// routed and role-gated, since the per-site cards were built -- but no template
// ever referenced them, so a stored override could be switched to "inherit" and
// never actually removed.  Sites accumulated records nobody could clear from
// the UI.
func TestScopeDeleteButtonRendered(t *testing.T) {
	var s settings.Settings
	s.Branding.Sites = map[string]settings.BrandingValues{"shop.example.com": {SiteName: "Shop"}}
	s.Challenge.Sites = map[string]settings.ChallengeValues{"shop.example.com": {PowDifficulty: 22}}
	h := deleteTestHandler(t, s)

	for _, tab := range []string{"branding", "challenge"} {
		page := "theme"
		if tab == "challenge" {
			page = "challenge"
		}
		body := renderSettings(t, h, "?tab="+page+"&scope=shop.example.com")
		btn := deleteButtonFor(body, tab)
		if btn == "" {
			t.Fatalf("%s tab: no delete button for a site that has a stored record", tab)
		}
		// It must target that site, not whatever the picker last held.
		if !strings.Contains(btn, "site=shop.example.com") {
			t.Errorf("%s tab: delete button does not carry the scope: %s", tab, btn)
		}
		// Destructive, so it asks first.
		if !strings.Contains(btn, "confirm(") {
			t.Errorf("%s tab: delete button skips the confirmation", tab)
		}
		// formnovalidate: the edit form's required/min/max inputs must not be
		// able to block a delete.
		if !strings.Contains(btn, "formnovalidate") {
			t.Errorf("%s tab: delete would be blocked by the edit form's validation", tab)
		}
	}
}

// TestScopeDeleteButtonHiddenWhenNothingStored: offering "delete" for a site
// that has no record would be a button that cannot do anything -- and on the
// Default scope it would read as an offer to delete the global settings.
func TestScopeDeleteButtonHiddenWhenNothingStored(t *testing.T) {
	h := deleteTestHandler(t, settings.Settings{})

	body := renderSettings(t, h, "?tab=theme&scope=fresh.example.com")
	if deleteButtonFor(body, "branding") != "" {
		t.Error("a site with no stored record was offered a delete button")
	}
	if body := renderSettings(t, h, "?tab=theme"); deleteButtonFor(body, "branding") != "" {
		t.Error("the Default scope was offered a per-site delete button")
	}
}

// TestScopeDeleteButtonShownForDisabledEntry: switching the override off keeps
// the record ("inherit for now, remember my values"), which is exactly the
// state where the operator needs a way to actually discard it.
func TestScopeDeleteButtonShownForDisabledEntry(t *testing.T) {
	var s settings.Settings
	s.Branding.Sites = map[string]settings.BrandingValues{
		"shop.example.com": {SiteName: "Shop", Disabled: true},
	}
	h := deleteTestHandler(t, s)

	body := renderSettings(t, h, "?tab=theme&scope=shop.example.com")
	if deleteButtonFor(body, "branding") == "" {
		t.Error("a disabled (inheriting) record offers no way to be discarded")
	}
}

// TestScopeDeleteActuallyRemoves: the button posts the edit form's own fields
// to the delete endpoint via formaction, so the endpoint has to be satisfied by
// that payload alone.
func TestScopeDeleteActuallyRemoves(t *testing.T) {
	var s settings.Settings
	s.Branding.Sites = map[string]settings.BrandingValues{"shop.example.com": {SiteName: "Shop"}}
	s.Challenge.Sites = map[string]settings.ChallengeValues{"shop.example.com": {PowDifficulty: 22}}
	h := deleteTestHandler(t, s)

	post := func(path string) {
		t.Helper()
		form := url.Values{"site": {"shop.example.com"}, "use_site_override": {"1"}}
		r := httptest.NewRequest(http.MethodPost, path+"?site=shop.example.com",
			strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		switch {
		case strings.Contains(path, "branding"):
			h.AdminBrandingSiteDelete(rr, r)
		default:
			h.AdminChallengeSiteDelete(rr, r)
		}
		if rr.Code >= 400 {
			t.Fatalf("%s: status %d", path, rr.Code)
		}
	}
	post("/unmask/admin/settings/branding/site/delete")
	post("/unmask/admin/settings/challenge/site/delete")

	got := *h.cfg()
	if _, ok := got.Branding.Sites["shop.example.com"]; ok {
		t.Error("the branding record survived its delete")
	}
	if _, ok := got.Challenge.Sites["shop.example.com"]; ok {
		t.Error("the challenge record survived its delete")
	}
	// And the site is back to inheriting.
	if got.Branding.Resolve("shop.example.com").SiteName != got.Branding.Default.SiteName {
		t.Error("the site did not return to the Default branding record")
	}
}
