package nginxconf

import (
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The native plugin matches the ban file's "<ip>|<ja4>" and "|<ja4>" rows
// on $unmask_ban_ja4, and the render defines it on $effective_ja4 -- the
// fingerprint the daemon logs (ja4=) and writes the rows from, which behind
// a trusted load balancer is the one the balancer forwarded.  Until 0.1.54
// the plugin keyed on its own handshake, the balancer's fingerprint there,
// and a JA4 ban never matched behind one.  The map must be there in both
// renders: the degraded one defines $client_ja4 as a constant, and the
// module's own fallback is the old key, so the map is what carries the fix.
func TestBanJA4KeyFollowsEffectiveJA4(t *testing.T) {
	re := regexp.MustCompile(`(?m)^map \$effective_ja4 \$unmask_ban_ja4 \{\n\s+default \$effective_ja4;\n\}`)
	for name, mutate := range map[string]func(*settings.Settings){
		"plain": nil,
		"behind an LB": func(s *settings.Settings) {
			s.Nginx.TrustedLBPresets = []string{"gcp"}
		},
	} {
		got := renderHTTPInc(t, mutate)
		if !re.MatchString(got) {
			t.Errorf("%s: http.inc must define $unmask_ban_ja4 as $effective_ja4:\n%s", name, got)
		}
	}
}
