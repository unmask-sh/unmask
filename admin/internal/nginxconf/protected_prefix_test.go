package nginxconf

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The rate-limit tab compares zone prefixes against protected-path patterns,
// which are nginx regexes -- the comparison only works through this reduction,
// so pin what it keeps and where it stops.
func TestProtectedPatternLiteralPrefix(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`^/unmask/admin/`, "/unmask/admin/"},
		{`^/wp-login\.php`, "/wp-login.php"}, // escaped literal survives
		{`^/wp-.*admin`, "/wp-"},             // stops at the first metachar
		{`^/manager/html`, "/manager/html"},
		{`/plain/prefix/`, "/plain/prefix/"}, // no anchor is fine
		{`^(?:/a|/b)/`, ""},                  // no literal head at all
	} {
		if got := ProtectedPatternLiteralPrefix(c.in); got != c.want {
			t.Errorf("%q -> %q, want %q", c.in, got, c.want)
		}
	}
}

// EffectiveProtectedPathRules is the render's composition, extracted so the
// settings UI warns against the set that is actually enforced.  Disabled rows
// and disabled presets must not produce warnings for paths nothing protects.
func TestEffectiveProtectedPathRulesHonoursEnablement(t *testing.T) {
	var s settings.Settings
	s.Nginx.ProtectedPaths.EnabledPresets = []string{"unmask"}
	s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{
		{Path: `^/checkout/`},
		{Path: `^/ignored/`, Disabled: true},
	}
	got := map[string]bool{}
	for _, r := range EffectiveProtectedPathRules(s) {
		got[r.Pattern] = true
	}
	if !got[`^/unmask/admin/`] {
		t.Error("the enabled unmask preset's pattern is missing")
	}
	if !got[`^/checkout/`] {
		t.Error("the enabled custom row is missing")
	}
	if got[`^/ignored/`] {
		t.Error("a disabled row leaked into the enforced set")
	}
	if got[`^/wp-admin/`] {
		t.Error("a disabled preset leaked into the enforced set")
	}
}
