package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A challenge-target preset held for upgrade review must be fully inert on the
// serve path too: its per-preset action must not steer the challenge chain for a
// visitor challenged by another axis.  (Regression for the ServeChallenge
// per-preset override that filtered only DisabledPresets, not the hold.)
func TestServeChallengeHeldPresetActionNotApplied(t *testing.T) {
	saved := nginxconf.ChallengeTargetGroups
	nginxconf.ChallengeTargetGroups = append(append([]nginxconf.ChallengeTargetGroup{}, saved...),
		nginxconf.ChallengeTargetGroup{
			ID:       "test_held_ct",
			Label:    "synthetic held target",
			AddedIn:  "v9.9.9",
			Patterns: []string{"TestHeldBot"},
		})
	t.Cleanup(func() { nginxconf.ChallengeTargetGroups = saved })

	h := newTestHandler(t)
	s := *h.cfg()
	s.Global.KnownBrowserAction = settings.RateChallengePoWOnly // the default pick for any challenged UA
	s.Nginx.ChallengeTargets.PresetAction = map[string]string{"test_held_ct": settings.RateChallengeCaptchaOnly}
	s.Nginx.EnforcementReviewedVersion = "v0.1.0" // older than the synthetic preset

	// review: the held preset's captcha action must NOT override the pow default.
	s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
	h.SetSettings(s)
	if got := servedChMode(t, h, "TestHeldBot/1.0"); got != settings.RateChallengePoWOnly {
		t.Errorf("held preset: chmode=%q, want pow_only (a held preset's action must be inert)", got)
	}

	// apply: the same preset's action applies (proving the test actually exercises
	// the override path, and that acknowledging activates it).
	s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewApply
	h.SetSettings(s)
	if got := servedChMode(t, h, "TestHeldBot/1.0"); got != settings.RateChallengeCaptchaOnly {
		t.Errorf("apply: chmode=%q, want captcha_only (the preset action applies once not held)", got)
	}
}
