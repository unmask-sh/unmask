package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestEvalOverBlock covers the breaker's trip decision: it needs BOTH enough
// serve volume AND a high serves-per-IP ratio (= the same visitors being
// re-challenged).  Either alone must not trip.
func TestEvalOverBlock(t *testing.T) {
	cfg := settings.OverBlockConfig{MinServes: 50, MaxServesPerIP: 4}
	// loads is what separates the case the breaker exists for from its
	// look-alike: a trapped visitor loads every challenge they are handed, a
	// scanner farm on a few addresses loads none while producing the same
	// serves-per-IP.  Loop cases therefore carry loads that track their serves.
	cases := []struct {
		name               string
		serves, ips, loads int
		wantOverBlock      bool
	}{
		{"healthy 1 serve per IP", 100, 100, 90, false},
		{"high ratio but volume below min", 40, 2, 40, false}, // 20/IP, but only 40 serves
		{"loop: same IPs re-served", 1000, 100, 900, true},    // 10/IP, plenty of volume
		{"exactly at both thresholds", 200, 50, 200, true},    // 4.0/IP, 200 serves
		{"ratio just under threshold", 50, 14, 50, false},     // ~3.57/IP < 4
		{"volume just under threshold", 49, 1, 49, false},     // 49/IP but 49 < 50 serves
		{"zero IPs (no traffic)", 0, 0, 0, false},
		// Measured on a production node while the alarm was up: Azure-hosted
		// web-shell probing, no user-agent, no TLS fingerprint, ONE load in ten
		// minutes.  139 serves/IP clears the ratio easily; nothing was stuck.
		{"scanner farm: high ratio, nobody runs the JS", 6403, 46, 1, false},
		// A loop that happens to share the window with a lot of bot noise must
		// still trip: the bar is one load per hundred serves, not a majority.
		{"loop hidden in bot noise", 6403, 46, 70, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, over, ratio := evalOverBlock(cfg, c.serves, c.ips, c.loads, false)
			if over != c.wantOverBlock {
				t.Errorf("overBlocking=%v want %v (serves=%d ips=%d ratio=%.2f)",
					over, c.wantOverBlock, c.serves, c.ips, ratio)
			}
		})
	}
}

// TestEvalOverBlockPassesTrippedThrough confirms evalOverBlock returns the
// current tripped state unchanged (the caller owns the transition).
func TestEvalOverBlockPassesTrippedThrough(t *testing.T) {
	cfg := settings.OverBlockConfig{MinServes: 50, MaxServesPerIP: 4}
	if tripped, _, _ := evalOverBlock(cfg, 0, 0, 0, true); !tripped {
		t.Error("evalOverBlock dropped the tripped state it was given")
	}
}

// TestOverBlockConfigDefaults locks the zero-value fallbacks (the daemon relies
// on them when the operator leaves fields unset).
func TestOverBlockConfigDefaults(t *testing.T) {
	var z settings.OverBlockConfig
	if z.WindowMinutesResolved() != 10 || z.MinServesResolved() != 50 || z.MaxServesPerIPResolved() != 4 {
		t.Errorf("zero-value defaults wrong: window=%d min=%d max=%d",
			z.WindowMinutesResolved(), z.MinServesResolved(), z.MaxServesPerIPResolved())
	}
	set := settings.OverBlockConfig{WindowMinutes: 5, MinServes: 10, MaxServesPerIP: 8}
	if set.WindowMinutesResolved() != 5 || set.MinServesResolved() != 10 || set.MaxServesPerIPResolved() != 8 {
		t.Error("explicit config values were not honored over the defaults")
	}
}
