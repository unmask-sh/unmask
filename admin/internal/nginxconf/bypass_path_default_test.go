// Tests for the per-preset DefaultOn resolution (EffectiveBypassPathPresets)
// and its wiring into the renderer: the config stores only deviations, so a
// fresh install (empty config) gets each preset's factory default, and a
// future preset added with its own default reaches old configs the same way.
package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The shipped defaults themselves: the four "machine access would silently
// break" groups are ON, api-paths (a plausible protection target) is OFF.
func TestShippedPresetDefaults(t *testing.T) {
	want := map[string]bool{
		"static-assets":    true,
		"well-known":       true,
		"browser-metadata": true,
		"health":           true,
		"api-paths":        false,
	}
	if len(BypassPathPresetGroups) != len(want) {
		t.Fatalf("preset count = %d, want %d (update this test when adding presets)", len(BypassPathPresetGroups), len(want))
	}
	for _, g := range BypassPathPresetGroups {
		w, ok := want[g.ID]
		if !ok {
			t.Errorf("unexpected preset %q (declare its default in this test)", g.ID)
			continue
		}
		if g.DefaultOn != w {
			t.Errorf("preset %s DefaultOn = %v, want %v", g.ID, g.DefaultOn, w)
		}
	}
}

func TestEffectiveBypassPathPresets(t *testing.T) {
	cases := []struct {
		name              string
		enabled, disabled []string
		wantOn            []string
		wantOff           []string
	}{
		{
			name:    "no deviations -> factory defaults",
			wantOn:  []string{"static-assets", "well-known", "browser-metadata", "health"},
			wantOff: []string{"api-paths"},
		},
		{
			name:     "default-ON preset explicitly disabled",
			disabled: []string{"well-known"},
			wantOn:   []string{"static-assets", "browser-metadata", "health"},
			wantOff:  []string{"well-known", "api-paths"},
		},
		{
			name:    "default-OFF preset explicitly enabled",
			enabled: []string{"api-paths"},
			wantOn:  []string{"static-assets", "well-known", "browser-metadata", "health", "api-paths"},
		},
		{
			name:     "unknown ids on both lists are ignored",
			enabled:  []string{"no-such-preset"},
			disabled: []string{"also-not-real"},
			wantOn:   []string{"static-assets", "well-known", "browser-metadata", "health"},
			wantOff:  []string{"api-paths"},
		},
		{
			// A legacy config that explicitly enabled a now-default-ON preset
			// stays ON (redundant entry, harmless).
			name:    "legacy explicit enable of a default-ON preset",
			enabled: []string{"static-assets"},
			wantOn:  []string{"static-assets"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveBypassPathPresets(tc.enabled, tc.disabled)
			for _, id := range tc.wantOn {
				if !got[id] {
					t.Errorf("%s should be ON", id)
				}
			}
			for _, id := range tc.wantOff {
				if got[id] {
					t.Errorf("%s should be OFF", id)
				}
			}
		})
	}
}

// The renderer applies the defaults: an empty config renders the default-ON
// presets' patterns, keeps api-paths out, and honours disabled_presets.
func TestRenderAppliesPresetDefaults(t *testing.T) {
	joined := func(d renderData) string { return strings.Join(d.BypassPathsGlobal, "\n") }

	// Empty config -> default-ON patterns present, default-OFF absent.
	s := settings.Settings{}
	d, err := buildRenderData(s, "", "0.1.0")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}
	out := joined(d)
	for _, pat := range []string{`^/\.well-known/`, `^/robots\.txt$`, `^/healthz$`, `^/manifest\.json$`} {
		if !strings.Contains(out, pat) {
			t.Errorf("default-ON pattern %q missing from render:\n%s", pat, out)
		}
	}
	if strings.Contains(out, `^/api/`+"\n") || strings.Contains(out, `^/graphql$`) {
		t.Errorf("default-OFF api-paths leaked into render:\n%s", out)
	}

	// disabled_presets removes a default-ON group.
	s2 := settings.Settings{}
	s2.Nginx.BypassPaths.DisabledPresets = []string{"well-known"}
	d2, err := buildRenderData(s2, "", "0.1.0")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}
	if strings.Contains(joined(d2), `^/\.well-known/`) {
		t.Errorf("disabled_presets did not remove well-known from render")
	}

	// A preset added AFTER the operator's last-seen version stays inert even
	// though DefaultOn (the NEW gate) -- simulate with an old SeenVersion.
	s3 := settings.Settings{}
	s3.Nginx.SeenVersion = "v0.0"
	d3, err := buildRenderData(s3, "", "0.1.0")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}
	if strings.Contains(joined(d3), `^/robots\.txt$`) {
		t.Errorf("NEW-gated preset rendered despite SeenVersion older than AddedIn")
	}
}
