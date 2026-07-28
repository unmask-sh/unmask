package handlers

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// overrideMapFrom pulls the JSON the page hands the inheritance-marker script.
func overrideMapFrom(t *testing.T, body string) map[string]bool {
	t.Helper()
	m := regexp.MustCompile(`(?s)<script type="application/json" class="field-overrides">(.*?)</script>`).
		FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the page did not emit a field-override map")
	}
	var out map[string]bool
	if err := json.Unmarshal([]byte(m[1]), &out); err != nil {
		t.Fatalf("override map is not valid JSON (%v): %s", err, m[1])
	}
	return out
}

func inheritTestHandler(t *testing.T, s settings.Settings) *Handler {
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

// TestPerSiteFormMarksInheritedFields: the per-site form is pre-filled with
// RESOLVED values, so a number the site pins looks exactly like one it borrows
// from the global record.  Per-field inheritance is only usable if the page
// says which is which -- otherwise an operator reading 18 next to "difficulty"
// cannot tell whether changing the global will move this site too.
func TestPerSiteFormMarksInheritedFields(t *testing.T) {
	var s settings.Settings
	s.Challenge.Default.PowDifficulty = 18
	s.Challenge.Default.DebugRateLimitPer5Min = 20
	s.Challenge.Sites = map[string]settings.ChallengeValues{
		"shop.example.com": {PowDifficulty: 22}, // only this one is the site's own
	}
	h := inheritTestHandler(t, s)

	over := overrideMapFrom(t, renderSettings(t, h, "?tab=challenge&scope=shop.example.com"))
	if !over["pow_difficulty"] {
		t.Error("the field the site actually sets is not marked as its own")
	}
	if over["debug_rate_limit_per_5min"] || over["pow_cookie_valid_seconds"] {
		t.Errorf("fields the site never set are claimed as overrides: %v", over)
	}
}

// TestDefaultScopeHasNoInheritanceMarkers: the Default record is the bottom of
// the chain, so marking its fields "inherited" would name a source that does
// not exist.
func TestDefaultScopeHasNoInheritanceMarkers(t *testing.T) {
	var s settings.Settings
	s.Challenge.Default.PowDifficulty = 18
	h := inheritTestHandler(t, s)

	body := renderSettings(t, h, "?tab=challenge")
	if strings.Contains(body, `class="field-overrides"`) {
		t.Error("the Default scope emitted per-field inheritance markers")
	}
}

// TestDisabledRecordShowsEverythingInherited: an override switched off is not
// applied, so every field on the form is coming from Default -- the markers
// have to say so rather than describing the remembered values as live.
func TestDisabledRecordShowsEverythingInherited(t *testing.T) {
	var s settings.Settings
	s.Challenge.Default.PowDifficulty = 18
	s.Challenge.Sites = map[string]settings.ChallengeValues{
		"shop.example.com": {PowDifficulty: 22, Disabled: true},
	}
	h := inheritTestHandler(t, s)

	over := overrideMapFrom(t, renderSettings(t, h, "?tab=challenge&scope=shop.example.com"))
	for k, v := range over {
		if v {
			t.Errorf("a disabled record still claims %q as an active override", k)
		}
	}
}
