package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Path lists must read the same on both wires.  The nginx render says which
// case rule a list follows -- "~" is case-sensitive, "~*" is not -- and this
// pins the forward-auth matchers to the same answer.  They diverged once:
// forward-auth folded "(?i)" into the PASS lists (bypass / geo-exempt /
// asn-exempt) while native rendered them with "~", so /STATIC/ skipped
// enforcement on one wire and took it on the other.
func TestPathMatcherCaseParityWithNativeRender(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.Nginx.BypassPaths.Paths = []settings.BypassPath{{Path: "^/static/"}}
	s.Nginx.Geo.ExemptPaths = []settings.BypassPath{{Path: "^/feed"}}
	s.Nginx.Asn.ExemptPaths = []settings.BypassPath{{Path: "^/rss"}}
	s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{{Path: "^/wp-admin/", Mode: nginxconf.ProtectedModeCaptcha}}
	s.Nginx.Honeypot.URLs = []settings.HoneypotURL{{Path: "^/trap/"}}
	h.SetSettings(s)

	if err := nginxconf.Render(s, dir, "test"); err != nil {
		t.Fatalf("render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	conf1 := string(b)

	// What the render committed to, read back out of the emitted maps.
	nativeInsensitive := func(pattern string) bool {
		for _, line := range strings.Split(conf1, "\n") {
			if !strings.Contains(line, pattern) || !strings.Contains(line, `"~`) {
				continue
			}
			return strings.Contains(line, `"~*`)
		}
		t.Fatalf("pattern %q never reached the rendered config", pattern)
		return false
	}

	pm := h.bypassMatchers(h.cfg(), "")
	matchesUpper := func(res []*regexp.Regexp, upper string) bool {
		for _, re := range res {
			if re.MatchString(upper) {
				return true
			}
		}
		return false
	}

	for _, c := range []struct {
		name    string
		pattern string
		upper   string
		fa      bool
	}{
		{"bypass", "^/static/", "/STATIC/x.js", matchesUpper(pm.bypass, "/STATIC/x.js")},
		{"geo exempt", "^/feed", "/FEED", matchesUpper(pm.geoExempt, "/FEED")},
		{"asn exempt", "^/rss", "/RSS", matchesUpper(pm.asnExempt, "/RSS")},
		{"protected", "^/wp-admin/", "/WP-ADMIN/", matchesUpper(pm.protected, "/WP-ADMIN/")},
	} {
		if want := nativeInsensitive(c.pattern); c.fa != want {
			t.Errorf("%s: forward-auth matches %q = %v, but the native render is case-insensitive = %v",
				c.name, c.upper, c.fa, want)
		}
	}

	// Honeypot carries its rules in a different shape; same assertion.
	hpUpper := false
	for _, r := range pm.honeypot {
		if r.re.MatchString("/TRAP/x") {
			hpUpper = true
		}
	}
	if want := nativeInsensitive("^/trap/"); hpUpper != want {
		t.Errorf("honeypot: forward-auth matches /TRAP/x = %v, native case-insensitive = %v", hpUpper, want)
	}
}

// Pass lists narrow, block lists widen: the direction each list resolves an
// ambiguous case is a security decision, so it is pinned rather than left to
// whichever regex flag someone reaches for next.
func TestPassListsAreCaseSensitiveBlockListsAreNot(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Nginx.BypassPaths.Paths = []settings.BypassPath{{Path: "^/static/"}}
	s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{{Path: "^/wp-admin/", Mode: nginxconf.ProtectedModeCaptcha}}
	h.SetSettings(s)
	pm := h.bypassMatchers(h.cfg(), "")

	passUpper := false
	for _, re := range pm.bypass {
		if re.MatchString("/STATIC/x.js") {
			passUpper = true
		}
	}
	if passUpper {
		t.Error("a pass list must not skip enforcement on a case variant it was never given")
	}
	blockUpper := false
	for _, re := range pm.protected {
		if re.MatchString("/WP-ADMIN/") {
			blockUpper = true
		}
	}
	if !blockUpper {
		t.Error("a block list must still catch the case variant")
	}
}

// Every path list states its pattern syntax up front.  The lists do not agree
// (rate-limit zones take a literal prefix, the rest take regex) and nothing on
// the screen shows which is which, so the help block is the only thing keeping
// an operator from writing ^/api/ into the one field that compares it byte for
// byte.
func TestEveryPathHelpStatesItsSyntax(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Nginx.AdvancedEnabled = true
	h.SetSettings(s)

	for _, c := range []struct{ tab, want string }{
		{"rate-limit", "literal prefix (NOT a regular expression)"},
		{"bypass-paths", "Pattern syntax: regular expression"},
		{"protected", "Pattern syntax: regular expression"},
		{"honeypot", "Pattern syntax: regular expression"},
		{"geo", "Pattern syntax: regular expression"},
		{"asn", "Pattern syntax: regular expression"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab="+c.tab, nil)
		req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s tab: %d", c.tab, rr.Code)
			continue
		}
		body := rr.Body.String()
		if !strings.Contains(body, c.want) {
			t.Errorf("%s tab does not state its pattern syntax (looking for %q)", c.tab, c.want)
		}
		if !strings.Contains(body, "path-syntax") {
			t.Errorf("%s tab is missing the syntax block markup", c.tab)
		}
	}
}
