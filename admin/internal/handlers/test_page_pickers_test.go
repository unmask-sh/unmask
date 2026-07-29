package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func renderTestIndex(t *testing.T, h *Handler, path string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	h.TestIndex(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: status %d", path, rr.Code)
	}
	return rr.Body.String()
}

func pickerValues(body, id string) []string {
	block := regexp.MustCompile(`(?s)<div id="` + id + `".*?</div>`).FindString(body)
	attr := map[string]string{
		"theme-picker": "data-theme", "preset-picker": "data-preset", "lang-picker": "data-lang",
	}[id]
	var out []string
	for _, m := range regexp.MustCompile(attr+`="([^"]*)"`).FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestThemePickerOffersEveryTheme: the test page existed to check how the
// challenge looks, but its theme list was missing two of the six -- light and
// auto -- so the two most ordinary looks were the ones you could not preview.
func TestThemePickerOffersEveryTheme(t *testing.T) {
	h := newTestHandler(t)
	got := pickerValues(renderTestIndex(t, h, "/unmask/admin/test/"), "theme-picker")

	have := map[string]bool{}
	for _, v := range got {
		have[v] = true
	}
	for name := range challengeThemes {
		if !have[name] {
			t.Errorf("theme %q is not offered on the test page", name)
		}
	}
	// Plus the inherit option, which is not a theme.
	if !have[""] {
		t.Error("the inherit option is missing")
	}
	if len(got) != len(challengeThemes)+1 {
		t.Errorf("picker has %d buttons, want %d themes + inherit", len(got), len(challengeThemes))
	}
}

// TestInheritButtonNamesTheValue: labelled "default", the inherit button read
// like a sixth theme sitting beside light / dark -- and there is no theme
// called "default".  It has to say what it actually inherits.
func TestInheritButtonNamesTheValue(t *testing.T) {
	h := newTestHandler(t)
	cfg := *h.cfg()
	cfg.Branding.Default.Theme = "paper"
	cfg.Branding.Sites = map[string]settings.BrandingValues{
		"shop.example.com": {Theme: "terminal", CopyPreset: settings.BrandingPresetMinimal},
	}
	h.SetSettings(cfg)

	body := renderTestIndex(t, h, "/unmask/admin/test/")
	// Scoped to the theme picker: the site picker also has a "default" button,
	// where it means "no site scoping" rather than naming a theme.
	themeBlock := regexp.MustCompile(`(?s)<div id="theme-picker".*?</div>`).FindString(body)
	if strings.Contains(themeBlock, `>default</button>`) {
		t.Error("the inherit button still calls itself a theme name")
	}
	if !strings.Contains(themeBlock, `data-inherit="theme"`) {
		t.Error("the inherit button is not marked for labelling")
	}

	// The label is filled client-side from this map, because the site picker
	// switches sites without reloading.
	m := regexp.MustCompile(`var SITE_CFG = (\{.*?\});`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the page did not ship the per-site config map")
	}
	var cfgMap map[string]map[string]string
	if err := json.Unmarshal([]byte(m[1]), &cfgMap); err != nil {
		t.Fatalf("config map is not valid JSON (%v): %s", err, m[1])
	}
	if cfgMap[""]["theme"] != "paper" {
		t.Errorf("default theme = %q, want the configured paper", cfgMap[""]["theme"])
	}
	if cfgMap["shop.example.com"]["theme"] != "terminal" {
		t.Errorf("site theme = %q, want terminal", cfgMap["shop.example.com"]["theme"])
	}
	if cfgMap["shop.example.com"]["preset"] != "minimal" {
		t.Errorf("site preset = %q, want minimal", cfgMap["shop.example.com"]["preset"])
	}
}

// TestUnsetThemeReportsItsFallback: a site that has set no theme still resolves
// to something, and naming that is the whole point of the label -- reporting an
// empty string would put the operator back where they started.
func TestUnsetThemeReportsItsFallback(t *testing.T) {
	h := newTestHandler(t)
	cfg := *h.cfg()
	cfg.Branding.Default.Theme = ""
	h.SetSettings(cfg)

	body := renderTestIndex(t, h, "/unmask/admin/test/")
	m := regexp.MustCompile(`var SITE_CFG = (\{.*?\});`).FindStringSubmatch(body)
	var cfgMap map[string]map[string]string
	json.Unmarshal([]byte(m[1]), &cfgMap)
	if cfgMap[""]["theme"] != "auto" {
		t.Errorf("unset theme reported as %q, want the auto it falls back to", cfgMap[""]["theme"])
	}
	if cfgMap[""]["preset"] == "" {
		t.Error("unset copy preset reported as empty rather than its resolved value")
	}
}

// TestWordingAndLanguagePickersPresent: the page could preview the theme but
// not the two other things that change what a visitor reads.
func TestWordingAndLanguagePickersPresent(t *testing.T) {
	h := newTestHandler(t)
	body := renderTestIndex(t, h, "/unmask/admin/test/")

	presets := pickerValues(body, "preset-picker")
	for _, want := range []string{"", "friendly", "neutral", "minimal"} {
		found := false
		for _, g := range presets {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("wording picker is missing %q", want)
		}
	}

	langs := pickerValues(body, "lang-picker")
	if len(langs) != 19 { // 18 locales + "visitor's browser"
		t.Errorf("language picker has %d entries, want 18 locales plus the inherit option", len(langs))
	}
	for _, want := range []string{"", "en", "ja", "ar", "hi"} {
		found := false
		for _, g := range langs {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("language picker is missing %q", want)
		}
	}
	// Language is not a per-site setting, so its inherit option must not claim
	// to be one.
	langBlock := regexp.MustCompile(`(?s)<div id="lang-picker".*?</div>`).FindString(body)
	if strings.Contains(langBlock, `data-inherit=`) {
		t.Error("the language picker offers a 'site setting' option, which does not exist for language")
	}
}
