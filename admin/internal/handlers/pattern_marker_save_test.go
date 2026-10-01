package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A marker typed into a pattern box on top of the one the page adds was
// stored twice, and the doubled value matched only text that still began with
// a marker -- an allowlist row that rescued nothing.  Every pattern list is
// normalized at the save intake: one marker kept, a box holding only a marker
// emptied (kept, "exact:" would match an empty value), regexes untouched, and
// lists that hold values rather than patterns left alone.
func TestNormalizePatternFields(t *testing.T) {
	const text = "ExampleBot/1.0"
	form := url.Values{}
	for _, f := range patternListFields {
		form[f] = []string{
			settings.ExactMarker + settings.ExactMarker + text,
			" " + settings.ContainsMarker + settings.ContainsMarker + text + " ",
			settings.ExactMarker,
			`^Mozilla/5\.0`,
		}
	}
	const notAPattern = settings.ExactMarker + settings.ExactMarker + "192.0.2.1"
	form["bypass_ip"] = []string{notAPattern}

	normalizePatternFields(form)

	want := []string{settings.ExactMarker + text, settings.ContainsMarker + text, "", `^Mozilla/5\.0`}
	for _, f := range patternListFields {
		if got := form[f]; strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s = %q, want %q", f, got, want)
		}
	}
	if got := form.Get("bypass_ip"); got != notAPattern {
		t.Errorf("bypass_ip holds values, not patterns, and was rewritten to %q", got)
	}
}

// The intake is wired into the save itself: a doubled value posted to two
// lists that different code reads lands in config.yml with one marker, and a
// marker-only row is dropped like a blank one.
func TestSettingsSaveStoresOneMarker(t *testing.T) {
	const text = "ExampleBot/1.0"
	h := ruleTestHandler(t)
	post := func(section string, form url.Values) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section="+section, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		if rr.Code >= 400 {
			t.Fatalf("saving %s: HTTP %d", section, rr.Code)
		}
	}
	post("ua-filter", url.Values{
		"white_extra":         {settings.ExactMarker + settings.ExactMarker + text, settings.ExactMarker},
		"white_extra_enabled": {"1", "1"},
	})
	post("bypass-paths", url.Values{
		"bp_path":    {settings.ContainsMarker + settings.ContainsMarker + "/feed/"},
		"bp_enabled": {"1"},
	})
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cur.Nginx.SearchBots.Extra, settings.ExactMarker+text; len(got) != 1 || got[0] != want {
		t.Errorf("search_bots.extra = %q, want [%q]", got, want)
	}
	if got, want := cur.Nginx.BypassPaths.Paths, settings.ContainsMarker+"/feed/"; len(got) != 1 || got[0].Path != want {
		t.Errorf("bypass_paths = %+v, want one path %q", got, want)
	}
}

// patternListFields has to name exactly the lists the settings page gives the
// mode chip.  A chip list missing from it would be the doubled-marker hole
// again on that list; a name with no chip would rewrite values that are not
// patterns.
func TestPatternListFieldsAreTheChipLists(t *testing.T) {
	h := newTestHandler(t)
	// Every tab, including the two that stay behind the advanced switch.
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Nginx.AdvancedEnabled = true })
	chip := regexp.MustCompile(`<span class="rule-pat-wrap"><input[^>]*\bname="([^"]+)"[^>]*>\s*<button[^>]*class="rule-pat-mode"`)
	onPage := map[string]bool{}
	for tab := range settingsTabs {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/"+tab+"/", nil)
		req.SetPathValue("tab", tab)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("tab %s: want 200, got %d", tab, rr.Code)
		}
		for _, m := range chip.FindAllStringSubmatch(rr.Body.String(), -1) {
			onPage[m[1]] = true
		}
	}
	inList := map[string]bool{}
	for _, f := range patternListFields {
		inList[f] = true
	}
	var missing, extra []string
	for f := range onPage {
		if !inList[f] {
			missing = append(missing, f)
		}
	}
	for f := range inList {
		if !onPage[f] {
			extra = append(extra, f)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("lists with the mode chip that the save does not normalize (add to patternListFields): %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("patternListFields names lists the page gives no chip: %v", extra)
	}
}

// A rule added from the hunt ranking goes through the same reading: one
// marker stored, whatever the dialog posted.
func TestHuntUARuleStoresOneMarker(t *testing.T) {
	h := ruleTestHandler(t)
	form := url.Values{
		"op":      {"ua_blacklist"},
		"pattern": {settings.ContainsMarker + settings.ContainsMarker + "ExampleBot"},
		"ua":      {"ExampleBot/1.0 (+https://example.org/bot)"},
		"title":   {"t"},
		"range":   {"1h"},
	}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/hunt/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey{}, &SessionPayload{UserID: 1, Role: "admin"}))
	h.AdminHuntAction(httptest.NewRecorder(), req)

	cur, err := settings.Load(filepath.Clean(h.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	got := cur.Nginx.ChallengeTargets.Extra
	if want := settings.ContainsMarker + "ExampleBot"; len(got) == 0 || got[len(got)-1] != want {
		t.Errorf("challenge_targets.extra = %q, want it to end with %q", got, want)
	}
}
