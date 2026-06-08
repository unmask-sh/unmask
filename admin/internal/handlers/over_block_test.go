package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestApplyOverBlockForm covers the global-settings form -> OverBlockConfig
// mapping, including the partial-submit safety (blank/garbage numeric fields
// keep the previous value rather than zeroing a threshold).
func TestApplyOverBlockForm(t *testing.T) {
	form := url.Values{
		"ob_enabled":           {"1"},
		"ob_window_minutes":    {"15"},
		"ob_min_serves":        {"80"},
		"ob_max_serves_per_ip": {"6"},
		"ob_auto_passthrough":  {"1"},
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var c settings.OverBlockConfig
	applyOverBlockForm(&c, r)
	if !c.Enabled || !c.AutoPassthrough || c.WindowMinutes != 15 || c.MinServes != 80 || c.MaxServesPerIP != 6 {
		t.Errorf("applied wrong: %+v", c)
	}

	// Unchecked checkboxes -> false; blank/garbage numerics keep the prior value.
	c2 := settings.OverBlockConfig{Enabled: true, WindowMinutes: 99, MinServes: 99, MaxServesPerIP: 99}
	r2 := httptest.NewRequest("POST", "/", strings.NewReader("ob_window_minutes=&ob_min_serves=abc&ob_max_serves_per_ip=0"))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	applyOverBlockForm(&c2, r2)
	if c2.Enabled {
		t.Error("unchecked ob_enabled should clear Enabled")
	}
	if c2.WindowMinutes != 99 || c2.MinServes != 99 || c2.MaxServesPerIP != 99 {
		t.Errorf("blank/garbage/zero numeric should keep previous: %+v", c2)
	}
}

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
