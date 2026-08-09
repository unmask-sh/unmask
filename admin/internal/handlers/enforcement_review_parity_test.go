package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The forward-auth in-memory matcher must hold a new enforcement preset exactly
// as the native render does -- otherwise a preset held inert in nginx would
// still fire on a forward-auth node, the kind of wire disagreement the matcher
// comments warn about.
func TestForwardAuthHoldsNewHoneypotUnderReview(t *testing.T) {
	saved := nginxconf.HoneypotPresetGroups
	nginxconf.HoneypotPresetGroups = append(append([]nginxconf.HoneypotGroup{}, saved...),
		nginxconf.HoneypotGroup{
			ID:       "test_future_hp",
			Label:    "synthetic future honeypot",
			AddedIn:  "v9.9.9",
			Patterns: []string{`^/test-future-honeypot$`},
		})
	t.Cleanup(func() { nginxconf.HoneypotPresetGroups = saved })

	h := newTestHandler(t)
	matches := func(policy, reviewed string) bool {
		var n settings.Nginx
		n.UpgradeReviewPolicy = policy
		n.EnforcementReviewedVersion = reviewed
		pm := h.bypassMatchers(&settings.Settings{Nginx: n}, "example.test")
		for _, r := range pm.honeypot {
			if r.re.MatchString("/test-future-honeypot") {
				return true
			}
		}
		return false
	}

	if !matches(settings.UpgradeReviewApply, "v0.1.0") {
		t.Error("apply: forward-auth must match a new honeypot preset immediately")
	}
	if matches(settings.UpgradeReviewReview, "v0.1.0") {
		t.Error("review + old reviewed: forward-auth must hold the new honeypot inert (native parity)")
	}
	if !matches(settings.UpgradeReviewReview, "v9.9.9") {
		t.Error("review + acknowledged: forward-auth must match once reviewed up to the preset version")
	}
}

// hardDenyUA (the forward-auth hard-deny derivation) must honor the hold too, or
// a held deny-action challenge-target would still deny on a forward-auth node
// while native holds it.
func TestForwardAuthHoldsNewDenyTargetUnderReview(t *testing.T) {
	saved := nginxconf.ChallengeTargetGroups
	nginxconf.ChallengeTargetGroups = append(append([]nginxconf.ChallengeTargetGroup{}, saved...),
		nginxconf.ChallengeTargetGroup{
			ID:       "test_future_ct",
			Label:    "synthetic future deny target",
			AddedIn:  "v9.9.9",
			Patterns: []string{"TestFutureBot"},
		})
	t.Cleanup(func() { nginxconf.ChallengeTargetGroups = saved })

	mk := func(policy, reviewed string) settings.Nginx {
		var n settings.Nginx
		n.UpgradeReviewPolicy = policy
		n.EnforcementReviewedVersion = reviewed
		n.ChallengeTargets.PresetAction = map[string]string{"test_future_ct": settings.RateChallengeDeny}
		return n
	}

	if !hardDenyUA("TestFutureBot", mk(settings.UpgradeReviewApply, "v0.1.0")) {
		t.Error("apply: a new deny challenge-target must deny in forward-auth")
	}
	if hardDenyUA("TestFutureBot", mk(settings.UpgradeReviewReview, "v0.1.0")) {
		t.Error("review + old reviewed: a held deny challenge-target must NOT deny (native parity)")
	}
}
