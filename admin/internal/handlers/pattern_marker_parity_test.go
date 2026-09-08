package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A pattern stored with a mode marker (contains: / exact:) must mean the same
// thing on every wire: the rendered nginx maps (rx), the forward-auth
// matchers, the serve-side protected-mode lookup and the honeypot action
// resolver.  The Go side used to compile the raw string, marker included, so a
// "contains:/feed/" bypass path matched nothing in forward-auth mode while the
// native config honoured it.
func TestMarkerPatternsMeanTheSameOnBothWires(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.Nginx.BypassPaths.Paths = []settings.BypassPath{{Path: "contains:/feed/"}}
	s.Nginx.Geo.ExemptPaths = []settings.BypassPath{{Path: "exact:/rss.xml"}}
	s.Nginx.Asn.ExemptPaths = []settings.BypassPath{{Path: "contains:/atom"}}
	s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{{Path: "contains:/wp-admin", Mode: nginxconf.ProtectedModeCaptcha}}
	s.Nginx.Honeypot.URLs = []settings.HoneypotURL{{Path: "exact:/trap", Action: "deny"}}
	h.SetSettings(s)

	// Native: the maps carry the resolved regex, never the marker.
	if err := nginxconf.Render(s, dir, "test"); err != nil {
		t.Fatalf("render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	httpInc := string(b)
	// The path maps are case-sensitive ("~"), the protected / honeypot maps
	// case-insensitive ("~*"); either way the marker is resolved.
	for _, want := range []string{`"~/feed/"`, `"~^/rss\.xml$"`, `"~/atom"`, `"~*/wp-admin"`, `"~*^/trap$"`} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("rendered http.inc lacks %s", want)
		}
	}
	for _, marker := range []string{"contains:", "exact:"} {
		if strings.Contains(httpInc, marker) {
			t.Errorf("a marker leaked into the rendered config: %s", marker)
		}
	}

	// Forward-auth: the matchers read the same patterns.
	pm := h.bypassMatchers(h.cfg(), "")
	matchAny := func(res []*regexp.Regexp, uri string) bool {
		for _, re := range res {
			if re.MatchString(uri) {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		name string
		res  []*regexp.Regexp
		uri  string
		want bool
	}{
		{"bypass contains", pm.bypass, "/blog/feed/", true},
		{"bypass contains, other path", pm.bypass, "/blog/", false},
		{"geo exact", pm.geoExempt, "/rss.xml", true},
		{"geo exact, escaped dot", pm.geoExempt, "/rssXxml", false},
		{"geo exact, longer", pm.geoExempt, "/rss.xml/more", false},
		{"asn contains", pm.asnExempt, "/feeds/atom", true},
		{"protected contains", pm.protected, "/site/wp-admin/edit.php", true},
	} {
		if got := matchAny(c.res, c.uri); got != c.want {
			t.Errorf("%s: forward-auth match(%q) = %v, want %v", c.name, c.uri, got, c.want)
		}
	}
	hpMatch := func(uri string) bool {
		for _, r := range pm.honeypot {
			if r.re.MatchString(uri) {
				return true
			}
		}
		return false
	}
	if !hpMatch("/trap") || hpMatch("/trap/x") {
		t.Errorf("honeypot exact: /trap must match and /trap/x must not (forward-auth)")
	}

	// Serve-side protected mode and the honeypot action resolver.
	if got := protectedModeForOrig(s.Nginx, "", "/site/wp-admin/edit.php"); got != nginxconf.ProtectedModeCaptcha {
		t.Errorf("protectedModeForOrig with a contains: rule = %q, want %q", got, nginxconf.ProtectedModeCaptcha)
	}
	if act, ok := nginxconf.ResolveHoneypotAction("/trap", "", s.Nginx); !ok || act != "deny" {
		t.Errorf("ResolveHoneypotAction(/trap) = (%q, %v), want (deny, true)", act, ok)
	}
	if _, ok := nginxconf.ResolveHoneypotAction("/trap/x", "", s.Nginx); ok {
		t.Errorf("an exact: honeypot URL must not match a longer path")
	}
}

// The save-time validators compile what the wires will compile: a literal
// (contains: / exact:) with regex metacharacters is accepted -- it is quoted
// on the way to the regex -- while the same text as a regex is refused.
func TestValidatorsCompileTheResolvedPattern(t *testing.T) {
	form := func(vals url.Values) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		return r
	}
	lang := i18n.Lang("en")
	const literal = "contains:/a(b"
	const broken = "/a(b"

	var n settings.Nginx
	if err := applyBypassPathsForm(&n, form(url.Values{"bp_path": {literal}, "bp_enabled": {"1"}}), lang); err != nil {
		t.Errorf("bypass path: a literal with a paren must be accepted, got %v", err)
	}
	if err := applyBypassPathsForm(&n, form(url.Values{"bp_path": {broken}, "bp_enabled": {"1"}}), lang); err == nil {
		t.Errorf("bypass path: an unbalanced regex must be refused")
	}
	if err := applyProtectedForm(&n, form(url.Values{"protected_path": {literal}, "protected_enabled": {"1"}, "protected_mode": {""}}), lang); err != nil {
		t.Errorf("protected path: literal accepted, got %v", err)
	}
	if err := applyProtectedForm(&n, form(url.Values{"protected_path": {broken}, "protected_enabled": {"1"}, "protected_mode": {""}}), lang); err == nil {
		t.Errorf("protected path: unbalanced regex refused")
	}
	if err := applyHoneypotForm(&n, form(url.Values{"honeypot_url_path": {literal}, "honeypot_url_enabled": {"1"}}), lang); err != nil {
		t.Errorf("honeypot url: literal accepted, got %v", err)
	}
	if err := applyHoneypotForm(&n, form(url.Values{"honeypot_url_path": {broken}, "honeypot_url_enabled": {"1"}}), lang); err == nil {
		t.Errorf("honeypot url: unbalanced regex refused")
	}
	var ex []settings.BypassPath
	if err := applyExemptPathsForm(&ex, "gx", form(url.Values{"gx_path": {literal}, "gx_enabled": {"1"}}), lang); err != nil {
		t.Errorf("geo exempt: literal accepted, got %v", err)
	}
	if err := applyExemptPathsForm(&ex, "gx", form(url.Values{"gx_path": {broken}, "gx_enabled": {"1"}}), lang); err == nil {
		t.Errorf("geo exempt: unbalanced regex refused")
	}
}
