package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The web-bot-auth tab renders the operator allowlist as preset checkboxes
// (checked = the host is in the allowlist) + custom add-rows.  A preset host
// must NOT also appear as a custom row, and the page must close (no truncation).
func TestSettingsWebBotAuthTabRenders(t *testing.T) {
	orig := settings.WebBotAuthOperatorPresets
	settings.WebBotAuthOperatorPresets = []settings.OperatorPreset{{Host: "openai.com", Label: "OpenAI", Since: "v0.1"}}
	t.Cleanup(func() { settings.WebBotAuthOperatorPresets = orig })

	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Nginx.AdvancedEnabled = true // master gate: gated tabs redirect when off
		s.Nginx.WebBotAuth = settings.WebBotAuthConfig{
			Enabled:          true,
			AllowedOperators: []string{"openai.com", "custom.example"},
		}
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=web-bot-auth", nil)
	req.SetPathValue("tab", "web-bot-auth")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`name="preset_operator" value="openai.com"`, // preset checkbox
		`since v0.1`,                             // provenance label
		`card-badge preset`,                      // preset section badge
		`card-badge custom`,                      // custom section badge
		`name="operator" value="custom.example"`, // custom row (not a preset)
		`wbaAddOperator()`,                       // add button
		`</html>`,                                // no truncation
	} {
		if !strings.Contains(body, want) {
			t.Errorf("web-bot-auth tab render missing %q", want)
		}
	}
	// openai.com is in the allowlist → its preset checkbox is checked.
	if !strings.Contains(body, `value="openai.com" checked`) {
		t.Error("an allowlisted preset must render checked")
	}
	// A preset host must not also render as a custom row (it lives in the preset
	// section, not the custom list).
	if strings.Contains(body, `name="operator" value="openai.com"`) {
		t.Error("a preset host must not also render as a custom row")
	}
}

func TestApplyWebBotAuthForm_PresetAndCustom(t *testing.T) {
	form := url.Values{}
	form.Set("enabled", "1")
	form.Add("preset_operator", "openai.com")
	form.Add("preset_operator", "Bing.com")
	form.Add("operator", "custom.example")
	form.Add("operator", "bing.com")   // case-insensitive dup of a preset → dropped
	form.Add("operator", "   ")        // blank → dropped
	form.Add("operator", "openai.com") // dup of a preset → dropped
	form.Set("cache_ttl_sec", "1800")
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var c settings.WebBotAuthConfig
	applyWebBotAuthForm(&c, req)

	if !c.Enabled {
		t.Error("enabled not set")
	}
	if c.CacheTTLSec != 1800 {
		t.Errorf("cache_ttl = %d, want 1800", c.CacheTTLSec)
	}
	// Presets first (in checkbox order), then custom rows, deduped case-insensitively.
	want := []string{"openai.com", "Bing.com", "custom.example"}
	if !slices.Equal(c.AllowedOperators, want) {
		t.Errorf("AllowedOperators = %v, want %v", c.AllowedOperators, want)
	}
}
