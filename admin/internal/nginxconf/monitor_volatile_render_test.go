package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Monitor mode's $unmask_enforce map was volatile on every install, and
// nginx before 1.11.7 -- the supported range starts at 1.10.3 -- does not
// know the word: turning monitor mode on (a setup wizard choice) made such
// an nginx refuse the configuration.  Only the veto-pass detours change the
// map's source within a request, so it is volatile with them alone.
func TestMonitorEnforceVolatileOnlyWithTheDetours(t *testing.T) {
	enforceMap := func(httpInc string) string {
		i := strings.Index(httpInc, `$unmask_enforce {`)
		if i < 0 {
			t.Fatal("no $unmask_enforce map")
		}
		j := strings.Index(httpInc[i:], "}")
		return httpInc[i : i+j]
	}
	plain, _, _ := renderIncs(t, func(s *settings.Settings) {
		s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
	})
	if m := enforceMap(plain); strings.Contains(m, "volatile") {
		t.Errorf("monitor mode without the detours is volatile:\n%s", m)
	}
	detours, _, _ := renderIncs(t, func(s *settings.Settings) {
		s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
		s.Nginx.AdvancedEnabled = true
		s.Nginx.WebBotAuth.Enabled = true
	})
	if m := enforceMap(detours); !strings.Contains(m, "volatile;") || !strings.Contains(detours, `map "$final_challenge_eff:$unmask_observe" $unmask_enforce {`) {
		t.Errorf("monitor mode with the detours is not volatile on the detour's decision:\n%s", m)
	}
}
