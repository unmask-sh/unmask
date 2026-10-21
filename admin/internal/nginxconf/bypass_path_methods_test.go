package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The default-ON presets name files that are only ever fetched, so they pass
// GET / HEAD / OPTIONS only: their patterns render into the safe-method map,
// not the any-method one.  An API or Git preset, and an operator's row, pass
// every method.
func TestBypassPresetsSafeMethods(t *testing.T) {
	has := func(list []string, p string) bool {
		for _, x := range list {
			if x == p {
				return true
			}
		}
		return false
	}

	d, err := buildRenderData(settings.Settings{}, "", "0.1.0")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}
	for _, p := range []string{`^/robots\.txt$`, `^/static/`, `^/\.well-known/`, `^/manifest\.json$`, `^/healthz$`} {
		if !has(d.BypassPathsGlobalSafe, p) {
			t.Errorf("default-ON preset pattern %q must render into the safe-method map; safe = %q", p, d.BypassPathsGlobalSafe)
		}
		if has(d.BypassPathsGlobal, p) {
			t.Errorf("default-ON preset pattern %q must not pass every method", p)
		}
	}

	var s settings.Settings
	s.Nginx.BypassPaths.EnabledPresets = []string{"api-paths", "git-http"}
	s.Nginx.BypassPaths.Paths = []settings.BypassPath{
		{Path: `^/robots\.txt$`},                    // the operator's own row for a preset's pattern
		{Path: `^/hooks/`},                          // an operator's path
		{Path: `^/feed/`, Site: "shop.example.com"}, // a per-site row
	}
	d, err = buildRenderData(s, "", "0.1.0")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}
	for _, p := range []string{`^/api/`, `^/graphql$`, `^/[^?]+/info/refs(?:\?|$)`, `^/hooks/`} {
		if !has(d.BypassPathsGlobal, p) || has(d.BypassPathsGlobalSafe, p) {
			t.Errorf("%q must pass every method", p)
		}
	}
	// The operator's row lifts the preset's restriction for that pattern.
	if !has(d.BypassPathsGlobal, `^/robots\.txt$`) || has(d.BypassPathsGlobalSafe, `^/robots\.txt$`) {
		t.Errorf("an operator's row for ^/robots\\.txt$ must pass every method; any = %q, safe = %q", d.BypassPathsGlobal, d.BypassPathsGlobalSafe)
	}
	if !has(d.BypassPathsGlobalSafe, `^/favicon\.ico$`) {
		t.Error("the rest of the preset keeps its restriction")
	}
	if len(d.BypassPathsPerHost) != 1 || d.BypassPathsPerHost[0].Host != "shop.example.com" || !has(d.BypassPathsPerHost[0].Patterns, `^/feed/`) {
		t.Errorf("per-site rows keep their per-host map: %+v", d.BypassPathsPerHost)
	}
}

// The render keeps the safe-method rules in the global map, which is only
// right while no preset rule names a site.
func TestSafeMethodPresetRulesAreGlobal(t *testing.T) {
	for _, g := range BypassPathPresetGroups {
		if !g.SafeMethodsOnly {
			continue
		}
		for _, r := range g.Rules {
			if r.Site != "" {
				t.Errorf("preset %s: rule %q names site %q; the safe-method map is global", g.ID, r.Pattern, r.Site)
			}
		}
	}
}

// http.inc: the safe-method map ANDs the path with GET / HEAD / OPTIONS, and
// $is_bypass_path takes it in both shapes (with and without per-site rows).
func TestBypassSafeMethodRender(t *testing.T) {
	for name, mutate := range map[string]func(*settings.Settings){
		"global only": nil,
		"per-site rows": func(s *settings.Settings) {
			s.Nginx.BypassPaths.Paths = []settings.BypassPath{{Path: `^/feed/`, Site: "shop.example.com"}}
		},
	} {
		inc := renderHTTPInc(t, mutate)
		for _, want := range []string{
			"map $uri $unmask_bp_safe_path {",
			`"~^/robots\.txt$" "1";`,
			`map "$request_method:$unmask_bp_safe_path" $unmask_bp_safe {`,
			`"GET:1"     "1";`,
			`"HEAD:1"    "1";`,
			`"OPTIONS:1" "1";`,
		} {
			if !strings.Contains(inc, want) {
				t.Errorf("%s: http.inc lacks %q", name, want)
			}
		}
		if strings.Contains(inc, `"POST:1"`) {
			t.Errorf("%s: POST must not pass a safe-method preset", name)
		}
		want := `map "$unmask_bp_global$unmask_bp_safe" $is_bypass_path {`
		if mutate != nil {
			want = `map "$unmask_bp_global$unmask_bp_safe$unmask_bp_per_host" $is_bypass_path {`
		}
		if !strings.Contains(inc, want) {
			t.Errorf("%s: $is_bypass_path must take the safe-method map: want %q", name, want)
		}
	}

	// Every default-ON preset off: the maps still render (the variable is
	// referenced either way), empty.
	inc := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassPaths.DisabledPresets = []string{"static-assets", "well-known", "browser-metadata", "health"}
	})
	i := strings.Index(inc, "map $uri $unmask_bp_safe_path {")
	if i < 0 {
		t.Fatal("the safe-method map must render with no preset on")
	}
	if body := inc[i : i+strings.Index(inc[i:], "}")]; strings.Contains(body, `"~`) {
		t.Errorf("no preset on, yet the safe-method map lists patterns:\n%s", body)
	}
}

func TestIsSafeMethod(t *testing.T) {
	for m, want := range map[string]bool{"GET": true, "head": true, "OPTIONS": true, "POST": false, "PUT": false, "PATCH": false, "DELETE": false, "": false} {
		if got := IsSafeMethod(m); got != want {
			t.Errorf("IsSafeMethod(%q) = %v, want %v", m, got, want)
		}
	}
}
