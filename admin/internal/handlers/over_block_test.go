package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestEvalOverBlock covers the breaker's trip decision: at least three stuck
// addresses AND at least half of those that ran the challenge.  On an
// ordinary day a busy site has a handful of stuck addresses among the many
// that ran the challenge, and on a quiet one a single stuck visitor can be a
// third of those who ran it.
func TestEvalOverBlock(t *testing.T) {
	var cfg settings.OverBlockConfig // the defaults: 3 addresses, 50%
	cases := []struct {
		name           string
		stuck, loaders int
		want           bool
	}{
		{"a loop: nearly everyone stuck", 9, 10, true},
		{"exactly at both lines", 3, 6, true},
		{"busy site, ordinary day", 5, 150, false},
		{"quiet site, one stuck visitor in three", 1, 3, false},
		{"two stuck, both of two: too few to say", 2, 2, false},
		{"just under the share", 3, 7, false}, // 42%
		{"nobody", 0, 0, false},
		// Stuck addresses whose loads fell just before the window: counted
		// among those that ran it.
		{"stuck, no loads in the window", 3, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := events.StuckReport{Stuck: c.stuck, Loaders: c.loaders}
			if got := evalOverBlock(cfg, r); got != c.want {
				t.Errorf("stuck %d of %d (%d%%): overBlocking=%v, want %v", c.stuck, c.loaders, r.StuckShare(), got, c.want)
			}
		})
	}
}

// TestOverBlockConfigDefaults locks the zero-value fallbacks (the daemon relies
// on them when the operator leaves fields unset).
func TestOverBlockConfigDefaults(t *testing.T) {
	var z settings.OverBlockConfig
	if z.WindowMinutesResolved() != 10 || z.LongWindowMinutesResolved() != 60 || z.MinStuckIPsResolved() != 3 || z.StuckPercentResolved() != 50 {
		t.Errorf("zero-value defaults: window %d, long %d, min %d, pct %d",
			z.WindowMinutesResolved(), z.LongWindowMinutesResolved(), z.MinStuckIPsResolved(), z.StuckPercentResolved())
	}
	set := settings.OverBlockConfig{WindowMinutes: 90, MinStuckIPs: 5, StuckPercent: 150}
	if set.WindowMinutesResolved() != 90 || set.LongWindowMinutesResolved() != 90 || set.MinStuckIPsResolved() != 5 || set.StuckPercentResolved() != 100 {
		t.Error("explicit config values were not honored (or the share not capped at 100)")
	}
}

// The admin's address for an alert's links: the first host the allowlist
// names; none from a list of patterns.
func TestAdminURL(t *testing.T) {
	s := settings.Settings{}
	s.Server.BasePath = "/unmask"
	if got := adminURL(s); got != "" {
		t.Errorf("no allowlist: %q", got)
	}
	s.Nginx.AdminAllowedHosts = []string{`^web\d+$`, "admin1", "exact:Admin.Example.com", "subdomain:example.org"}
	if got := adminURL(s); got != "https://admin.example.com/unmask" {
		t.Errorf("adminURL = %q", got)
	}
	s.Nginx.AdminAllowedHostsDisabled = []bool{false, false, true}
	if got := adminURL(s); got != "https://example.org/unmask" {
		t.Errorf("with the exact entry switched off: %q", got)
	}
}
