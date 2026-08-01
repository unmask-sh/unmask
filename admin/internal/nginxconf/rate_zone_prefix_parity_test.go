package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A zone's path patterns are LITERAL prefixes -- that is what the column says
// and what RateZone.MatchPath does.  Native mode drops them into an nginx
// regex, so they must be escaped on the way in.  Before this, the same config
// enforced two different things depending on deploy mode: forward-auth
// compared bytes while native ran the pattern as a case-insensitive regex.
func TestZonePathPrefixesAreEscapedIntoTheNginxRegex(t *testing.T) {
	conf := renderHTTPInc(t, func(s *settings.Settings) {
		s.RateLimit.Zones = []settings.RateZone{
			{Name: "dotted", PathPatterns: []string{"/api/v1.0/"}, RequestsPerMin: 5},
		}
	})
	if !strings.Contains(conf, `"~^/api/v1\.0/"`) {
		t.Errorf("the dot was not escaped, so native would match any character there:\n%s",
			grepLines(conf, "/api/v1"))
	}
	// Case-insensitive matching was the other half of the divergence: URLs are
	// case-sensitive and MatchPath compares bytes, so the render must not use
	// the ~* form.
	if strings.Contains(conf, `"~*^/api/v1`) {
		t.Error("native still matches this prefix case-insensitively; forward-auth does not")
	}
}

// A pattern carrying regex syntax must not reach nginx as syntax: unescaped,
// "/a(b" is an unterminated group and `nginx -t` fails -- which disables the
// whole module, not just this zone.
func TestZonePathWithRegexSyntaxCannotBreakTheConfig(t *testing.T) {
	conf := renderHTTPInc(t, func(s *settings.Settings) {
		s.RateLimit.Zones = []settings.RateZone{
			{Name: "weird", PathPatterns: []string{"/a(b", "/c[d", "/e+f"}, RequestsPerMin: 5},
		}
	})
	for _, raw := range []string{`"~^/a(b"`, `"~^/c[d"`, `"~^/e+f"`} {
		if strings.Contains(conf, raw) {
			t.Errorf("unescaped regex syntax reached the config: %s", raw)
		}
	}
	for _, want := range []string{`/a\(b`, `/c\[d`, `/e\+f`} {
		if !strings.Contains(conf, want) {
			t.Errorf("expected the escaped form %q in the render", want)
		}
	}
}

// Both wires agree on what a prefix means.  The Go side is the reference
// (MatchPath); the render is checked to carry the same literal, escaped.
func TestPrefixSemanticsMatchAcrossWires(t *testing.T) {
	z := settings.RateZone{Name: "z", PathPatterns: []string{"/api/v1.0/"}}
	// forward-auth: literal, so a URI that only matches as a regex must NOT hit.
	if !z.MatchPath("/api/v1.0/x") {
		t.Error("the literal prefix should match its own path")
	}
	if z.MatchPath("/api/v1X0/") {
		t.Error("MatchPath treated the dot as a regex wildcard")
	}
	// native: the rendered pattern is the escaped literal, so it cannot match
	// /api/v1X0/ either.
	conf := renderHTTPInc(t, func(s *settings.Settings) {
		s.RateLimit.Zones = []settings.RateZone{z}
	})
	if !strings.Contains(conf, `v1\.0`) {
		t.Error("the rendered pattern is not the escaped literal, so the wires can still disagree")
	}
}

func grepLines(s, needle string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, needle) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
