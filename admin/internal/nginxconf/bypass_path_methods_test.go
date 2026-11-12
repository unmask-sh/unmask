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

// An operator's row set to GET / HEAD / OPTIONS only renders beside the
// presets' rules, not in the every-method map: a row for every site in the
// global safe-method map, a row for one site in that site's own.
func TestOperatorRowsSafeMethods(t *testing.T) {
	has := func(list []string, p string) bool {
		for _, x := range list {
			if x == p {
				return true
			}
		}
		return false
	}
	hostPats := func(list []BypassPathHostMaps, host string) []string {
		for _, h := range list {
			if h.Host == host {
				return h.Patterns
			}
		}
		return nil
	}

	var s settings.Settings
	s.Nginx.BypassPaths.EnabledPresets = []string{"api-paths"}
	s.Nginx.BypassPaths.Paths = []settings.BypassPath{
		{Path: `^/feed/`, SafeMethodsOnly: true}, // every site, fetched only
		{Path: `^/hooks/`},                       // every site, every method
		{Path: `^/rss\.xml$`, Site: "shop.example.com", SafeMethodsOnly: true}, // one site, fetched only
		{Path: `^/cart/api/`, Site: "shop.example.com"},                        // one site, every method
		{Path: `^/off/`, SafeMethodsOnly: true, Disabled: true},                // switched off
		// The same pattern twice for one site: the wider row stands.
		{Path: `^/both/`, SafeMethodsOnly: true},
		{Path: `^/both/`},
		// A restricted row for a pattern a restricted preset already names
		// keeps the restriction; one for an every-method preset's pattern
		// does not narrow the preset the operator switched on.
		{Path: `^/robots\.txt$`, SafeMethodsOnly: true},
		{Path: `^/api/`, SafeMethodsOnly: true},
	}
	d, err := buildRenderData(s, "", "0.1.0")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}
	for _, p := range []string{`^/feed/`, `^/robots\.txt$`} {
		if !has(d.BypassPathsGlobalSafe, p) || has(d.BypassPathsGlobal, p) {
			t.Errorf("%q must pass GET / HEAD / OPTIONS only; any = %q, safe = %q", p, d.BypassPathsGlobal, d.BypassPathsGlobalSafe)
		}
	}
	for _, p := range []string{`^/hooks/`, `^/both/`, `^/api/`} {
		if !has(d.BypassPathsGlobal, p) || has(d.BypassPathsGlobalSafe, p) {
			t.Errorf("%q must pass every method; any = %q, safe = %q", p, d.BypassPathsGlobal, d.BypassPathsGlobalSafe)
		}
	}
	if has(d.BypassPathsGlobalSafe, `^/off/`) || has(d.BypassPathsGlobal, `^/off/`) {
		t.Error("a row switched off must render nowhere")
	}
	if got := hostPats(d.BypassPathsPerHostSafe, "shop.example.com"); len(got) != 1 || got[0] != `^/rss\.xml$` {
		t.Errorf("the site's safe-method map = %q, want only ^/rss\\.xml$", got)
	}
	if got := hostPats(d.BypassPathsPerHost, "shop.example.com"); len(got) != 1 || got[0] != `^/cart/api/` {
		t.Errorf("the site's every-method map = %q, want only ^/cart/api/", got)
	}
}

// http.inc with a per-site safe-method row: the site's own map, the
// dispatcher, the two path results ORed, and the method gate reading that.
// Without such a row the gate reads the global map directly, as it did.
func TestBypassSafeMethodPerHostRender(t *testing.T) {
	inc := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassPaths.Paths = []settings.BypassPath{
			{Path: `^/rss\.xml$`, Site: "shop.example.com", SafeMethodsOnly: true},
			{Path: `^/cart/api/`, Site: "shop.example.com"},
		}
	})
	for _, want := range []string{
		"map $uri $unmask_bps_host_shop_example_com {",
		`"~^/rss\\.xml$" "1";`,
		"map $host $unmask_bp_safe_per_host {",
		`"shop.example.com" $unmask_bps_host_shop_example_com;`,
		`map "$unmask_bp_safe_path$unmask_bp_safe_per_host" $unmask_bp_safe_hit {`,
		`map "$request_method:$unmask_bp_safe_hit" $unmask_bp_safe {`,
		// The every-method row keeps its own per-host map and dispatcher.
		"map $uri $unmask_bp_host_shop_example_com {",
		`"~^/cart/api/" "1";`,
		`map "$unmask_bp_global$unmask_bp_safe$unmask_bp_per_host" $is_bypass_path {`,
	} {
		if !strings.Contains(inc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	// The site's fetched-only pattern is in no every-method map.
	i := strings.Index(inc, "map $uri $unmask_bp_host_shop_example_com {")
	if i < 0 {
		t.Fatal("no every-method map for the site")
	}
	if body := inc[i : i+strings.Index(inc[i:], "}")]; strings.Contains(body, `rss`) {
		t.Errorf("the fetched-only row is in the site's every-method map:\n%s", body)
	}

	// Only safe-method rows for the site: no every-method per-host stage.
	inc = renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassPaths.Paths = []settings.BypassPath{{Path: `^/rss\.xml$`, Site: "shop.example.com", SafeMethodsOnly: true}}
	})
	if strings.Contains(inc, "$unmask_bp_per_host") {
		t.Error("no every-method row names a site, yet the every-method dispatcher rendered")
	}
	if want := `map "$unmask_bp_global$unmask_bp_safe" $is_bypass_path {`; !strings.Contains(inc, want) {
		t.Errorf("http.inc lacks %q", want)
	}

	// No per-site safe-method row: the gate reads the global map, and none of
	// the per-site stage renders.
	inc = renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassPaths.Paths = []settings.BypassPath{{Path: `^/feed/`, SafeMethodsOnly: true}}
	})
	if want := `map "$request_method:$unmask_bp_safe_path" $unmask_bp_safe {`; !strings.Contains(inc, want) {
		t.Errorf("http.inc lacks %q", want)
	}
	for _, not := range []string{"$unmask_bp_safe_per_host", "$unmask_bp_safe_hit", "$unmask_bps_host_"} {
		if strings.Contains(inc, not) {
			t.Errorf("no per-site safe-method row, yet http.inc carries %q", not)
		}
	}
	if !strings.Contains(inc, `"~^/feed/" "1";`) {
		t.Error("the operator's fetched-only row is missing from the safe-method map")
	}
}

// Two sites whose names differ only by a leading "safe." must not meet in one
// variable: the every-method maps and the safe-method maps keep prefixes of
// their own, and no map variable is defined twice.
func TestBypassSafeMethodPerHostVarNames(t *testing.T) {
	inc := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassPaths.Paths = []settings.BypassPath{
			{Path: `^/a/`, Site: "safe.example.com"},
			{Path: `^/b/`, Site: "example.com", SafeMethodsOnly: true},
		}
	})
	seen := map[string]int{}
	for _, line := range strings.Split(inc, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "map" && f[len(f)-1] == "{" {
			seen[f[len(f)-2]]++
		}
	}
	for _, v := range []string{"$unmask_bp_host_safe_example_com", "$unmask_bps_host_example_com"} {
		if seen[v] != 1 {
			t.Errorf("map variable %s defined %d times, want once", v, seen[v])
		}
	}
	for v, n := range seen {
		if n > 1 && strings.HasPrefix(v, "$unmask_bp") {
			t.Errorf("map variable %s defined %d times", v, n)
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
			`"~^/robots\\.txt$" "1";`,
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
