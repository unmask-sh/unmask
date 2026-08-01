package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A zone's path patterns are case-insensitive REGEXES -- the same grammar as
// the protected-path and honeypot lists, and what RateZone.MatchPath compiles.
// The pair has diverged twice: first native ran them as regex while
// forward-auth compared bytes, then (after that was aligned on the literal
// reading) the product carried one path field whose grammar differed from
// every other.  This pins the shared answer from the render side.
func TestZonePathPatternsRenderAsCaseInsensitiveRegex(t *testing.T) {
	conf := renderHTTPInc(t, func(s *settings.Settings) {
		s.RateLimit.Zones = []settings.RateZone{
			{Name: "api", PathPatterns: []string{`^/(api|graphql)/`}, RequestsPerMin: 5},
		}
	})
	if !strings.Contains(conf, `"~*^/(api|graphql)/"`) {
		t.Error("the pattern did not reach nginx as a case-insensitive regex")
	}
	// The escaping the literal era required must be gone: an escaped
	// alternation would match the characters "(api|graphql)" verbatim.
	if strings.Contains(conf, `\(api`) {
		t.Error("the pattern is still being escaped; regex syntax would match literally")
	}
}

// Both wires answer the same question the same way, including case.
func TestZonePathMatchAgreesWithTheRender(t *testing.T) {
	z := settings.RateZone{Name: "api", PathPatterns: []string{`^/api/`}}
	for _, c := range []struct {
		path string
		want bool
	}{
		{"/api/v1/things", true},
		{"/API/v1/things", true}, // ~* on the native side
		{"/foo/api/v1", false},   // anchored, so not a substring match
		{"/apix", false},
	} {
		if got := z.MatchPath(c.path); got != c.want {
			t.Errorf("MatchPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}

	// Unanchored patterns match anywhere, which is what a regex means and what
	// the syntax help tells the operator to anchor against.
	sub := settings.RateZone{Name: "sub", PathPatterns: []string{`/api/`}}
	if !sub.MatchPath("/foo/api/v1") {
		t.Error("an unanchored pattern should match mid-path (regex semantics)")
	}
}

// A pattern that does not compile must never match rather than matching
// everything: the settings form refuses these on save, so one here means a
// hand-edited config, and a rate limit nobody can read applying to every
// request is the worse failure.
func TestZonePathBadPatternMatchesNothing(t *testing.T) {
	z := settings.RateZone{Name: "broken", PathPatterns: []string{"/a(b"}}
	if z.MatchPath("/a(b") || z.MatchPath("/anything") {
		t.Error("an unparsable pattern must not match")
	}
}
