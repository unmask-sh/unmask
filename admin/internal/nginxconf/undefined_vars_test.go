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
	// A map or a geo is one where a line starts with the word.  Taken
	// anywhere, the word "map" in a comment opened a match that ran to the
	// last variable ahead of the next brace, and every `set` in between --
	// each a definition of its own -- was swallowed without being counted.
	defRe := regexp.MustCompile(`(?m)(?:^[ \t]*map\b[^{]*\$|set\s+\$|^[ \t]*geo\b[^{]*\$)(unmask_[a-z0-9_]+)`)
	tmplActionRe := regexp.MustCompile(`\{\{[^}]*\}\}`)
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
		// Without the template's own actions (a space in the place of each,
		// so the words on either side stay apart): a map whose source is
		// spelled with one ("{{ if .X }}$a{{ else }}$b{{ end }}:...") has a
		// brace ahead of the variable it defines, and defRe stops at a brace.
		s := tmplActionRe.ReplaceAllString(string(b), " ")
		for _, m := range useRe.FindAllStringSubmatch(s, -1) {
			used[m[1]] = true
		}
		for _, m := range defRe.FindAllStringSubmatch(s, -1) {
			defined[m[1]] = true
		}
	}

	// The gateway image's own nginx.conf defines what the gateway's rendered
	// files read from it ($unmask_gw_xfp, in gateway-location.inc).  That
	// one used to pass on the comment beside its use, which says "The map is
	// the image's" (see defRe).
	images, _ := filepath.Glob(filepath.Join("..", "..", "..", "docker", "nginx", "*.template"))
	if len(images) == 0 {
		t.Fatal("no docker/nginx/*.template found -- can't read the gateway image's own variables")
	}
	for _, f := range images {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range defRe.FindAllStringSubmatch(string(b), -1) {
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
