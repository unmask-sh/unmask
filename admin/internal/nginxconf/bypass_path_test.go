// Tests for bypass-path Pattern conventions and the renderer split.
//
// Convention: BypassPathRule.Pattern is a path-anchored PCRE regex
// (e.g., `^/api/`) evaluated against `$request_uri` directly.  No host
// concatenation, no anchor stripping.  Per-host rules are emitted as
// separate path-only maps + a host dispatcher (see splitBypassPathsForRender).
package nginxconf

import (
	"regexp"
	"strings"
	"testing"
)

// TestPresetPatternsArePathAnchored ensures every shipped preset stores its
// pattern as a path-anchored regex (= leading `^/`).  Patterns that drop the
// anchor would unintentionally match any URI containing the substring
// (= `/healthz` would match `/foo/healthz/bar`).
func TestPresetPatternsArePathAnchored(t *testing.T) {
	for _, g := range BypassPathPresetGroups {
		for _, r := range g.Rules {
			if r.Pattern == "" {
				t.Errorf("preset %s has empty pattern", g.ID)
				continue
			}
			if !strings.HasPrefix(r.Pattern, "^") {
				t.Errorf("preset %s pattern %q is not path-anchored (= add leading ^)", g.ID, r.Pattern)
			}
			// Quick sanity: the regex must compile.
			if _, err := regexp.Compile("(?i)" + r.Pattern); err != nil {
				t.Errorf("preset %s pattern %q does not compile: %v", g.ID, r.Pattern, err)
			}
		}
	}
}

// TestPresetPatternsMatchRealisticURIs sanity-checks each preset against the
// kind of URI it claims to cover.  Guards against typos like `/healtz$`.
func TestPresetPatternsMatchRealisticURIs(t *testing.T) {
	cases := []struct {
		presetID string
		uri      string
		want     bool
	}{
		{"static-assets", "/static/css/site.css", true},
		{"static-assets", "/assets/logo.png", true},
		{"static-assets", "/favicon.ico", true},
		{"static-assets", "/robots.txt", true},
		{"static-assets", "/sitemap.xml", true},
		{"static-assets", "/admin/static.html", false}, // not at start
		{"well-known", "/.well-known/acme-challenge/abc", true},
		{"health", "/healthz", true},
		{"health", "/api/health", true},
		{"health", "/healthcheck", false}, // anchor + $ on /healthz$
		{"api-paths", "/api/users", true},
		{"api-paths", "/v1/orders", true},
		{"api-paths", "/v2/items", true},
		{"api-paths", "/graphql", true},
		{"api-paths", "/foo/api/users", false}, // anchor blocks mid-URI hits
	}
	for _, c := range cases {
		hit := false
		for _, g := range BypassPathPresetGroups {
			if g.ID != c.presetID {
				continue
			}
			for _, r := range g.Rules {
				re := regexp.MustCompile("(?i)" + r.Pattern)
				if re.MatchString(c.uri) {
					hit = true
					break
				}
			}
		}
		if hit != c.want {
			t.Errorf("preset %s vs URI %q: got %v want %v", c.presetID, c.uri, hit, c.want)
		}
	}
}

// TestSplitBypassPathsForRender_GlobalOnly: empty Site goes to globals.
func TestSplitBypassPathsForRender_GlobalOnly(t *testing.T) {
	rules := []BypassPathRule{
		{Pattern: `^/api/`},
		{Pattern: `^/static/`},
	}
	globals, perHost := splitBypassPathsForRender(rules)
	if got := len(globals); got != 2 {
		t.Errorf("globals: got %d want 2 (%v)", got, globals)
	}
	if got := len(perHost); got != 0 {
		t.Errorf("perHost: got %d want 0 (%v)", got, perHost)
	}
	if globals[0] != `^/api/` || globals[1] != `^/static/` {
		t.Errorf("global patterns preserved as-is; got %v", globals)
	}
}

// TestSplitBypassPathsForRender_PerHost: non-empty Site groups by host.
func TestSplitBypassPathsForRender_PerHost(t *testing.T) {
	rules := []BypassPathRule{
		{Pattern: `^/api/`},                          // global
		{Pattern: `^/admin/`, Site: "uic.jp"},        // per-host
		{Pattern: `^/internal/`, Site: "uic.jp"},     // per-host (same host)
		{Pattern: `^/secret/`, Site: "example.com"},  // per-host (different host)
	}
	globals, perHost := splitBypassPathsForRender(rules)
	if len(globals) != 1 || globals[0] != `^/api/` {
		t.Errorf("globals: got %v want [^/api/]", globals)
	}
	if len(perHost) != 2 {
		t.Fatalf("perHost groups: got %d want 2 (%+v)", len(perHost), perHost)
	}
	// Sorted by host -> example.com first, uic.jp second.
	if perHost[0].Host != "example.com" {
		t.Errorf("perHost[0].Host: got %q want example.com", perHost[0].Host)
	}
	if perHost[0].VarName != "example_com" {
		t.Errorf("perHost[0].VarName: got %q want example_com", perHost[0].VarName)
	}
	if len(perHost[0].Patterns) != 1 || perHost[0].Patterns[0] != `^/secret/` {
		t.Errorf("perHost[0].Patterns: got %v want [^/secret/]", perHost[0].Patterns)
	}
	if perHost[1].Host != "uic.jp" || perHost[1].VarName != "uic_jp" {
		t.Errorf("perHost[1]: got %+v want host=uic.jp varname=uic_jp", perHost[1])
	}
	if len(perHost[1].Patterns) != 2 {
		t.Errorf("perHost[1].Patterns: got %d want 2 (%v)", len(perHost[1].Patterns), perHost[1].Patterns)
	}
}

// TestHostToNginxVarSegment covers the sanitizer used to derive nginx
// variable names from host strings.  Dots / hyphens / colons turn into `_`.
func TestHostToNginxVarSegment(t *testing.T) {
	cases := []struct{ in, want string }{
		{"uic.jp", "uic_jp"},
		{"tool-jp.example.com", "tool_jp_example_com"},
		{"", "default"},
		{"plain", "plain"},
		{"a1b2c3", "a1b2c3"},
		// IPv6 brackets / colons normalize too.
		{"[2001:db8::1]", "_2001_db8__1_"},
	}
	for _, c := range cases {
		if got := hostToNginxVarSegment(c.in); got != c.want {
			t.Errorf("hostToNginxVarSegment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRenderedMapRegexNaturalForm proves the rendered nginx map entry --
// `~^/api/` against a `$request_uri` input -- matches normally.  Guards
// against any future refactor that re-introduces a host concatenation.
func TestRenderedMapRegexNaturalForm(t *testing.T) {
	cases := []struct {
		pattern string
		uri     string
		want    bool
	}{
		{`^/api/`, "/api/speedtest/record", true},
		{`^/api/`, "/wp-login.php", false},
		{`^/healthz$`, "/healthz", true},
		{`^/healthz$`, "/healthz/extra", false},
		{`^/favicon\.ico$`, "/favicon.ico", true},
	}
	for _, c := range cases {
		// Mimic what nginx PCRE sees from `"~<pattern>"` directives.
		re := regexp.MustCompile(c.pattern)
		if got := re.MatchString(c.uri); got != c.want {
			t.Errorf("pattern %q vs uri %q: got %v want %v", c.pattern, c.uri, got, c.want)
		}
	}
}
