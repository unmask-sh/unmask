package settings

import (
	"reflect"
	"testing"
)

// ProtectedPathsConfig.Resolve: same shape as BypassPaths plus the per-site
// DefaultAction scalar.  Confirms append + remove on Paths, pointer-set on
// EnabledPresets, and empty-string-inherits on DefaultAction.  The returned
// value never carries the Overrides map (= callers must not re-resolve).
func TestProtectedPathsResolve(t *testing.T) {
	emptyPresets := []string{}
	customPresets := []string{"common-admin"}
	base := ProtectedPathsConfig{
		EnabledPresets: []string{"unmask"},
		Paths: []ProtectedPath{
			{Path: "^/admin/", Title: "default admin", Mode: "captcha"},
			{Path: "^/dashboard/", Title: "default dashboard", Mode: "captcha"},
		},
		DefaultAction: "pow_then_captcha",
		PresetAction:  map[string]string{"unmask": "captcha_only"},
		Overrides: map[string]ProtectedPathsOverride{
			"shop.example.com": {
				Append: []ProtectedPath{{Path: "^/checkout/admin/", Title: "shop", Mode: "captcha"}},
				Remove: []string{"^/dashboard/"},
			},
			"blog.example.com": {
				DefaultAction: "captcha_only",
			},
			"strict.example.com": {
				EnabledPresets: &emptyPresets,
				DefaultAction:  "deny",
			},
			"custom.example.com": {
				EnabledPresets: &customPresets,
			},
			"empty.example.com": {},
			"removeonly.example.com": {
				Remove: []string{"^/admin/"},
			},
			"emptyaction.example.com": {
				// Empty DefaultAction must inherit the default's
				// (= operator can blank a per-site action without leaving
				// a stale value).
				DefaultAction: "",
			},
		},
	}

	cases := []struct {
		name        string
		site        string
		wantPresets []string
		wantPaths   []ProtectedPath
		wantAction  string
	}{
		{
			name:        "no site -> default",
			site:        "",
			wantPresets: []string{"unmask"},
			wantPaths: []ProtectedPath{
				{Path: "^/admin/", Title: "default admin", Mode: "captcha"},
				{Path: "^/dashboard/", Title: "default dashboard", Mode: "captcha"},
			},
			wantAction: "pow_then_captcha",
		},
		{
			name:        "undeclared site -> default",
			site:        "api.example.com",
			wantPresets: []string{"unmask"},
			wantPaths: []ProtectedPath{
				{Path: "^/admin/", Title: "default admin", Mode: "captcha"},
				{Path: "^/dashboard/", Title: "default dashboard", Mode: "captcha"},
			},
			wantAction: "pow_then_captcha",
		},
		{
			name:        "append + remove -> drop + add",
			site:        "shop.example.com",
			wantPresets: []string{"unmask"},
			wantPaths: []ProtectedPath{
				{Path: "^/admin/", Title: "default admin", Mode: "captcha"},
				{Path: "^/checkout/admin/", Title: "shop", Mode: "captcha"},
			},
			wantAction: "pow_then_captcha",
		},
		{
			name:        "DefaultAction override only -> default paths + override scalar",
			site:        "blog.example.com",
			wantPresets: []string{"unmask"},
			wantPaths: []ProtectedPath{
				{Path: "^/admin/", Title: "default admin", Mode: "captcha"},
				{Path: "^/dashboard/", Title: "default dashboard", Mode: "captcha"},
			},
			wantAction: "captcha_only",
		},
		{
			name:        "EnabledPresets explicit empty + DefaultAction override",
			site:        "strict.example.com",
			wantPresets: []string{},
			wantPaths: []ProtectedPath{
				{Path: "^/admin/", Title: "default admin", Mode: "captcha"},
				{Path: "^/dashboard/", Title: "default dashboard", Mode: "captcha"},
			},
			wantAction: "deny",
		},
		{
			name:        "EnabledPresets replace -> override list wins",
			site:        "custom.example.com",
			wantPresets: []string{"common-admin"},
			wantPaths: []ProtectedPath{
				{Path: "^/admin/", Title: "default admin", Mode: "captcha"},
				{Path: "^/dashboard/", Title: "default dashboard", Mode: "captcha"},
			},
			wantAction: "pow_then_captcha",
		},
		{
			name:        "empty override entry -> default verbatim",
			site:        "empty.example.com",
			wantPresets: []string{"unmask"},
			wantPaths: []ProtectedPath{
				{Path: "^/admin/", Title: "default admin", Mode: "captcha"},
				{Path: "^/dashboard/", Title: "default dashboard", Mode: "captcha"},
			},
			wantAction: "pow_then_captcha",
		},
		{
			name:        "remove only -> default minus removed",
			site:        "removeonly.example.com",
			wantPresets: []string{"unmask"},
			wantPaths: []ProtectedPath{
				{Path: "^/dashboard/", Title: "default dashboard", Mode: "captcha"},
			},
			wantAction: "pow_then_captcha",
		},
		{
			name:        "empty DefaultAction override -> inherit",
			site:        "emptyaction.example.com",
			wantPresets: []string{"unmask"},
			wantPaths: []ProtectedPath{
				{Path: "^/admin/", Title: "default admin", Mode: "captcha"},
				{Path: "^/dashboard/", Title: "default dashboard", Mode: "captcha"},
			},
			wantAction: "pow_then_captcha",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := base.Resolve(tc.site)
			if !reflect.DeepEqual(got.EnabledPresets, tc.wantPresets) {
				t.Errorf("EnabledPresets = %v, want %v", got.EnabledPresets, tc.wantPresets)
			}
			if !reflect.DeepEqual(got.Paths, tc.wantPaths) {
				t.Errorf("Paths = %v, want %v", got.Paths, tc.wantPaths)
			}
			if got.DefaultAction != tc.wantAction {
				t.Errorf("DefaultAction = %q, want %q", got.DefaultAction, tc.wantAction)
			}
			if got.Overrides != nil {
				t.Errorf("Overrides leaked into resolved value: %v", got.Overrides)
			}
			// PresetAction must always survive resolution (= no per-site
			// PresetAction override surface in v0.1, so it's inherited from
			// the default verbatim).
			if !reflect.DeepEqual(got.PresetAction, base.PresetAction) {
				t.Errorf("PresetAction = %v, want %v", got.PresetAction, base.PresetAction)
			}
		})
	}
}

// EnabledPresets nil vs empty for ProtectedPaths: same pointer distinction as
// BypassPaths.  Confirms yaml round-trip semantics (`enabled_presets: ~` vs
// `enabled_presets: []`).
func TestProtectedPathsResolveEnabledPresetsPointer(t *testing.T) {
	emptySlice := []string{}
	base := ProtectedPathsConfig{
		EnabledPresets: []string{"unmask", "common-admin"},
		Overrides: map[string]ProtectedPathsOverride{
			"explicit-empty.example.com": {EnabledPresets: &emptySlice},
			"inherit.example.com":        {},
		},
	}
	if got := base.Resolve("explicit-empty.example.com").EnabledPresets; !reflect.DeepEqual(got, []string{}) {
		t.Errorf("explicit empty: got %v want []", got)
	}
	if got := base.Resolve("inherit.example.com").EnabledPresets; !reflect.DeepEqual(got, []string{"unmask", "common-admin"}) {
		t.Errorf("inherit: got %v want default", got)
	}
}
