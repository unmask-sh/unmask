package settings

import (
	"reflect"
	"testing"
)

// BypassPathsConfig.Resolve: site overrides combine with the default via
// append + remove on Paths and pointer-set on EnabledPresets.  Undeclared
// site / empty override entry fall through to the default.  The returned
// value never carries the Overrides map (= callers must not re-resolve).
func TestBypassPathsResolve(t *testing.T) {
	emptyPresets := []string{}
	customPresets := []string{"well-known", "static-assets"}
	base := BypassPathsConfig{
		EnabledPresets: []string{"health"},
		Paths: []BypassPath{
			{Path: "^/keep/", Title: "keep me"},
			{Path: "^/drop/", Title: "drop on shop"},
		},
		Overrides: map[string]BypassPathsOverride{
			"shop.example.com": {
				Append: []BypassPath{{Path: "^/checkout/", Title: "shop add"}},
				Remove: []string{"^/drop/"},
			},
			"blog.example.com": {
				Append: []BypassPath{{Path: "^/feed/", Title: "blog feed"}},
			},
			"strict.example.com": {
				EnabledPresets: &emptyPresets,
			},
			"custom.example.com": {
				EnabledPresets: &customPresets,
			},
			"empty.example.com": {},
			"removeonly.example.com": {
				Remove: []string{"^/keep/"},
			},
		},
	}

	cases := []struct {
		name         string
		site         string
		wantPresets  []string
		wantPaths    []BypassPath
	}{
		{
			name:        "no site -> default",
			site:        "",
			wantPresets: []string{"health"},
			wantPaths: []BypassPath{
				{Path: "^/keep/", Title: "keep me"},
				{Path: "^/drop/", Title: "drop on shop"},
			},
		},
		{
			name:        "undeclared site -> default",
			site:        "api.example.com",
			wantPresets: []string{"health"},
			wantPaths: []BypassPath{
				{Path: "^/keep/", Title: "keep me"},
				{Path: "^/drop/", Title: "drop on shop"},
			},
		},
		{
			name:        "append + remove -> drop + add",
			site:        "shop.example.com",
			wantPresets: []string{"health"},
			wantPaths: []BypassPath{
				{Path: "^/keep/", Title: "keep me"},
				{Path: "^/checkout/", Title: "shop add"},
			},
		},
		{
			name:        "append only -> default + add",
			site:        "blog.example.com",
			wantPresets: []string{"health"},
			wantPaths: []BypassPath{
				{Path: "^/keep/", Title: "keep me"},
				{Path: "^/drop/", Title: "drop on shop"},
				{Path: "^/feed/", Title: "blog feed"},
			},
		},
		{
			name:        "EnabledPresets explicit empty -> every preset off",
			site:        "strict.example.com",
			wantPresets: []string{},
			wantPaths: []BypassPath{
				{Path: "^/keep/", Title: "keep me"},
				{Path: "^/drop/", Title: "drop on shop"},
			},
		},
		{
			name:        "EnabledPresets replace -> override list wins",
			site:        "custom.example.com",
			wantPresets: []string{"well-known", "static-assets"},
			wantPaths: []BypassPath{
				{Path: "^/keep/", Title: "keep me"},
				{Path: "^/drop/", Title: "drop on shop"},
			},
		},
		{
			name:        "empty override entry -> default verbatim",
			site:        "empty.example.com",
			wantPresets: []string{"health"},
			wantPaths: []BypassPath{
				{Path: "^/keep/", Title: "keep me"},
				{Path: "^/drop/", Title: "drop on shop"},
			},
		},
		{
			name:        "remove only -> default minus removed",
			site:        "removeonly.example.com",
			wantPresets: []string{"health"},
			wantPaths: []BypassPath{
				{Path: "^/drop/", Title: "drop on shop"},
			},
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
			if got.Overrides != nil {
				t.Errorf("Overrides leaked into resolved value: %v", got.Overrides)
			}
		})
	}
}

// EnabledPresets nil vs empty: confirm the pointer distinction is preserved
// across Resolve (= a *[]string{} override produces [], a nil override
// inherits the default).  Important because yaml round-trips both shapes.
func TestBypassPathsResolveEnabledPresetsPointer(t *testing.T) {
	emptySlice := []string{}
	base := BypassPathsConfig{
		EnabledPresets: []string{"health", "well-known"},
		Overrides: map[string]BypassPathsOverride{
			"explicit-empty.example.com": {EnabledPresets: &emptySlice},
			"inherit.example.com":        {},
		},
	}
	if got := base.Resolve("explicit-empty.example.com").EnabledPresets; !reflect.DeepEqual(got, []string{}) {
		t.Errorf("explicit empty: got %v want []", got)
	}
	if got := base.Resolve("inherit.example.com").EnabledPresets; !reflect.DeepEqual(got, []string{"health", "well-known"}) {
		t.Errorf("inherit: got %v want default", got)
	}
}
