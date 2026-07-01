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
	cases := []struct {
		name          string
		serves, ips   int
		wantOverBlock bool
	}{
		{"healthy 1 serve per IP", 100, 100, false},
		{"high ratio but volume below min", 40, 2, false}, // 20/IP, but only 40 serves
		{"loop: same IPs re-served", 1000, 100, true},     // 10/IP, plenty of volume
		{"exactly at both thresholds", 200, 50, true},     // 4.0/IP, 200 serves
		{"ratio just under threshold", 50, 14, false},     // ~3.57/IP < 4
		{"volume just under threshold", 49, 1, false},     // 49/IP but 49 < 50 serves
		{"zero IPs (no traffic)", 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, over, ratio := evalOverBlock(cfg, c.serves, c.ips, false)
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
	if tripped, _, _ := evalOverBlock(cfg, 0, 0, true); !tripped {
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
