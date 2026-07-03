package nginxconf

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// TestNoUndefinedUnmaskVars guards against the class of bug that silently
// disabled the HTTPS redirect (2026-07-03): server.inc referenced
// $unmask_https_redirect, but the map that computed it had been removed, so the
// variable was undefined.  nginx treats an undefined $unmask_* as the empty
// string (it does NOT emerg), so `if ($undefined = "1")` is always false and the
// feature silently never fires -- a no-op that `nginx -t` cannot catch and that
// no other test noticed.  Every $unmask_* referenced in a template must be
// defined by either the C plugin (ngx_http_add_variable(..., ngx_string("x")))
// or a map/set/geo in the templates.
func TestNoUndefinedUnmaskVars(t *testing.T) {
	const tmplDir = "templates"
	pluginSrc := filepath.Join("..", "..", "..", "nginx-module", "src")

	useRe := regexp.MustCompile(`\$(unmask_[a-z0-9_]+)`)
	// map "<src>" $unmask_x {   |   set $unmask_x ...   |   geo ... $unmask_x {
	defRe := regexp.MustCompile(`(?:map\b[^{]*\$|set\s+\$|geo\b[^{]*\$)(unmask_[a-z0-9_]+)`)
	// ngx_http_add_variable(cf, ngx_string("unmask_x"), ...)
	pluginRe := regexp.MustCompile(`ngx_string\("(unmask_[a-z0-9_]+)"\)`)

	used := map[string]bool{}
	defined := map[string]bool{}

	tmpls, err := filepath.Glob(filepath.Join(tmplDir, "*.tmpl"))
	if err != nil || len(tmpls) == 0 {
		t.Fatalf("no *.tmpl found under %s (cwd=%s): %v", tmplDir, mustGetwd(), err)
	}
	for _, f := range tmpls {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, m := range useRe.FindAllStringSubmatch(s, -1) {
			used[m[1]] = true
		}
		for _, m := range defRe.FindAllStringSubmatch(s, -1) {
			defined[m[1]] = true
		}
	}

	// C plugin variables (native mode) -- registered in the module source, not
	// the templates.  Read them so a native-only variable isn't flagged.
	if srcs, _ := filepath.Glob(filepath.Join(pluginSrc, "*.c")); len(srcs) > 0 {
		for _, f := range srcs {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, m := range pluginRe.FindAllStringSubmatch(string(b), -1) {
				defined[m[1]] = true
			}
		}
	} else {
		t.Fatalf("no plugin *.c found under %s -- can't build the native-variable allowlist", pluginSrc)
	}

	var undef []string
	for v := range used {
		if !defined[v] {
			undef = append(undef, "$"+v)
		}
	}
	sort.Strings(undef)
	if len(undef) > 0 {
		t.Errorf("undefined $unmask_* variable(s) -- a typo, or a map/set removed "+
			"without dropping its uses; nginx treats these as the empty string so "+
			"the feature silently no-ops (the 2026-07-03 https_redirect regression): %v", undef)
	}
}

func mustGetwd() string {
	d, _ := os.Getwd()
	return d
}
