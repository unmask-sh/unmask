package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestHeaderIntegrityDefaultsOn: the axis ships enabled.  Its catch population
// is measured as almost purely non-human and it is clamped to a challenge, so
// the out-of-the-box posture includes it rather than waiting for an operator to
// discover the checkbox.
func TestHeaderIntegrityDefaultsOn(t *testing.T) {
	// Load a path that cannot exist so the loader returns pure defaults
	// (ResolvePath falls back to /etc/unmask/config.yml for "").
	s, err := settings.Load(t.TempDir() + "/absent.yml")
	if err == nil {
		t.Fatal("expected a read error for the absent file")
	}
	if !s.Global.HeaderIntegrity {
		t.Error("header integrity must default to on")
	}
	// Clamped to a challenge -- never a hard block, whatever is stored.
	if got := s.Global.HeaderIntegrityResolvedAction(); got == settings.RateChallengeDeny {
		t.Errorf("resolved action = %q, must never be deny", got)
	}
}

// TestHeaderBeatsStaleOnTie: a stale Chromium that is also missing its client
// hints fires both axes at the same default severity.  Both deploy modes must
// name the same one -- header, the sharper signal -- or the same visitor is
// attributed differently depending on how unmask is deployed, and the per-axis
// dashboards disagree about which wall did the work.
func TestHeaderBeatsStaleOnTie(t *testing.T) {
	header := axisDecision{sev: sevCaptchaOnly, reason: "header:no_sch_ua"}
	stale := axisDecision{sev: sevCaptchaOnly, reason: "ua:stale_browser:captcha_only"}

	// Registration order is what breaks the tie (pickStrongest keeps the first
	// at the winning severity); header is registered first in AuthCheck.
	win, _ := pickStrongest([]axisDecision{header, stale})
	if win.reason != "header:no_sch_ua" {
		t.Errorf("tie went to %q, want the header axis", win.reason)
	}

	// A genuinely stronger UA action still wins -- the tie-break must not
	// override severity ordering.
	strongerStale := axisDecision{sev: sevPoWThenCaptcha, reason: "ua:stale_browser:pow_then_captcha"}
	if sevPoWThenCaptcha > sevCaptchaOnly {
		win, _ = pickStrongest([]axisDecision{header, strongerStale})
		if win.reason != strongerStale.reason {
			t.Errorf("stronger axis lost the vote: got %q", win.reason)
		}
	}
}
