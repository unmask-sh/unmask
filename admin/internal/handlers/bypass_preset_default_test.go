package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func bypassPresetForm(t *testing.T, n *settings.Nginx, checkedIDs ...string) {
	t.Helper()
	form := url.Values{}
	for _, id := range checkedIDs {
		form.Add("bypass_path_preset_enabled", id)
	}
	req := httptest.NewRequest("POST", "/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("parse form: %v", err)
	}
	if err := applyBypassPathsForm(n, req, i18n.Lang("en")); err != nil {
		t.Fatalf("applyBypassPathsForm: %v", err)
	}
}

// The save records only deviations from each preset's DefaultOn.
func TestBypassPresetSaveStoresDeviationsOnly(t *testing.T) {
	// All checkboxes match the factory defaults -> nothing stored.
	n := settings.Nginx{}
	bypassPresetForm(t, &n, "static-assets", "well-known", "browser-metadata", "health")
	if len(n.BypassPaths.EnabledPresets) != 0 || len(n.BypassPaths.DisabledPresets) != 0 {
		t.Fatalf("default-matching save stored deviations: enabled=%v disabled=%v",
			n.BypassPaths.EnabledPresets, n.BypassPaths.DisabledPresets)
	}

	// Unchecking a default-ON preset -> disabled list.
	n2 := settings.Nginx{}
	bypassPresetForm(t, &n2, "static-assets", "browser-metadata", "health") // well-known unchecked
	if got := n2.BypassPaths.DisabledPresets; len(got) != 1 || got[0] != "well-known" {
		t.Fatalf("disabled = %v, want [well-known]", got)
	}
	if len(n2.BypassPaths.EnabledPresets) != 0 {
		t.Fatalf("enabled should be empty, got %v", n2.BypassPaths.EnabledPresets)
	}

	// Checking a default-OFF preset -> enabled list.
	n3 := settings.Nginx{}
	bypassPresetForm(t, &n3, "static-assets", "well-known", "browser-metadata", "health", "api-paths")
	if got := n3.BypassPaths.EnabledPresets; len(got) != 1 || got[0] != "api-paths" {
		t.Fatalf("enabled = %v, want [api-paths]", got)
	}

	// Unknown IDs (form tampering) are dropped.
	n4 := settings.Nginx{}
	bypassPresetForm(t, &n4, "static-assets", "well-known", "browser-metadata", "health", "no-such-id")
	if len(n4.BypassPaths.EnabledPresets) != 0 || len(n4.BypassPaths.DisabledPresets) != 0 {
		t.Fatalf("unknown id leaked: enabled=%v disabled=%v",
			n4.BypassPaths.EnabledPresets, n4.BypassPaths.DisabledPresets)
	}
}

// SeenVersion no longer affects the save: the opt-in gate was removed, so every
// preset's checkbox is live in the form and the form is authoritative.  An old
// SeenVersion neither preserves deviations behind the operator's back nor
// changes which deviations the form records.
func TestBypassPresetSaveIgnoresSeenVersion(t *testing.T) {
	// Old SeenVersion, form checks exactly the factory-default set -> no
	// deviations recorded, identical to a current save.
	n := settings.Nginx{SeenVersion: "v0.0"}
	bypassPresetForm(t, &n, "static-assets", "well-known", "browser-metadata", "health")
	if len(n.BypassPaths.EnabledPresets) != 0 || len(n.BypassPaths.DisabledPresets) != 0 {
		t.Fatalf("old SeenVersion changed the save: enabled=%v disabled=%v",
			n.BypassPaths.EnabledPresets, n.BypassPaths.DisabledPresets)
	}

	// Checking a default-OFF preset records it even on an old SeenVersion.
	n2 := settings.Nginx{SeenVersion: "v0.0"}
	bypassPresetForm(t, &n2, "static-assets", "well-known", "browser-metadata", "health", "api-paths")
	if got := n2.BypassPaths.EnabledPresets; len(got) != 1 || got[0] != "api-paths" {
		t.Fatalf("enabled = %v, want [api-paths] regardless of SeenVersion", got)
	}
}

// The forward-auth in-memory matcher applies the same defaults: an empty
// config bypasses /.well-known/ but not /api/, and (with the opt-in gate
// removed) a default-ON preset is active regardless of SeenVersion.
func TestBypassMatchersApplyPresetDefaults(t *testing.T) {
	h := newTestHandler(t)

	match := func(n settings.Nginx, uri string) bool {
		pm := h.bypassMatchers(&settings.Settings{Nginx: n}, "example.test")
		for _, re := range pm.bypass {
			if re.MatchString(uri) {
				return true
			}
		}
		return false
	}

	n := settings.Nginx{}
	if !match(n, "/.well-known/acme-challenge/tok") {
		t.Errorf("default-ON well-known should bypass")
	}
	if !match(n, "/robots.txt") {
		t.Errorf("default-ON static-assets should bypass robots.txt")
	}
	if match(n, "/api/users") {
		t.Errorf("default-OFF api-paths must NOT bypass")
	}

	n2 := settings.Nginx{}
	n2.BypassPaths.DisabledPresets = []string{"well-known"}
	if match(n2, "/.well-known/acme-challenge/tok") {
		t.Errorf("disabled_presets should remove well-known from the matcher")
	}

	n3 := settings.Nginx{SeenVersion: "v0.0"} // gate removed: SeenVersion no longer holds presets back
	if !match(n3, "/robots.txt") {
		t.Errorf("default-ON preset must be active in the matcher regardless of SeenVersion (gate removed)")
	}
}
