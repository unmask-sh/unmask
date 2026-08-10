package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A preset the operator pinned to a chain must resolve the same on both wires.
// lookupUAListed used to drop the action on a preset match -- returning "" so
// the caller fell back to the tab default -- while the native render read
// ChallengeTargets.PresetAction.  A preset pinned to a CAPTCHA chain was
// therefore enforced on native and not behind a load balancer, and the
// CAPTCHA-grade gate (which reads this same lookup) let a self-minted
// proof-of-work cookie through there: the exact hole that gate exists to close.
func TestUAPresetActionReachesBothWires(t *testing.T) {
	// The shipped "empty" preset matches a very short UA.  Resolved from the
	// live group list rather than hardcoded, so a renamed ID fails loudly here
	// instead of silently skipping the parity check.
	groupID, ua := "", "ab"
	for _, g := range nginxconf.ChallengeTargetGroups {
		if g.ID == "empty" {
			groupID = g.ID
		}
	}
	if groupID == "" {
		t.Fatal(`the "empty" challenge-target preset is gone -- point this parity test at another one`)
	}

	var cfg settings.Settings
	// The install's own default is the lighter chain; the preset is pinned harder.
	cfg.Nginx.ChallengeTargets.DefaultAction = settings.RateChallengePoWOnly
	cfg.Nginx.ChallengeTargets.PresetAction = map[string]string{groupID: settings.RateChallengeCaptchaOnly}

	listed, category, act := lookupUAListed(ua, cfg.Nginx)
	if listed != groupID || category != "challenge" {
		t.Fatalf("UA %q should match preset %q, got listed=%q category=%q", ua, groupID, listed, category)
	}
	if act != settings.RateChallengeCaptchaOnly {
		t.Errorf("preset action = %q, want the pinned captcha_only (dropping it falls back to the tab default and diverges from native)", act)
	}
	// The grade gate reads the same lookup, so it now demands a real CAPTCHA.
	if !uaRequiresCaptchaGrade(ua, cfg) {
		t.Error("a preset pinned to a captcha chain must require a CAPTCHA-grade cookie on this wire too")
	}
	// And the axis decision agrees rather than serving the tab default.
	if d, ok := uaDecide(ua, "", cfg, nil); !ok || d.chMode != settings.RateChallengeCaptchaOnly {
		t.Errorf("uaDecide = %+v ok=%v, want the preset's captcha_only", d, ok)
	}
}
