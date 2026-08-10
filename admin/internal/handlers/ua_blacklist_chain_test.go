package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Every wire must answer "what does a black-listed UA walk into?" identically.
// They did not: the forward-auth axis carried a hardcoded captcha_only from
// before the ua-filter picker existed, while the native serve path, the
// CAPTCHA-grade calculation and the admin UI all inherited the install
// default.  One black-listed visitor, two experiences, and the screens
// described only one of them.
func TestUABlacklistChainAgreesAcrossWires(t *testing.T) {
	const bot = "BadBot/1.0 (+https://example.com/bot)"

	for _, c := range []struct {
		name       string
		defaultAct string
		rateMode   string
		want       string
	}{
		{"both unset -> shipped default", "", "", settings.RateChallengePoWThenCaptcha},
		{"install default drives it", "", settings.RateChallengePoWOnly, settings.RateChallengePoWOnly},
		{"picker wins over install default", settings.RateChallengeCaptchaOnly, settings.RateChallengePoWOnly, settings.RateChallengeCaptchaOnly},
		{"picker set to the chain", settings.RateChallengePoWThenCaptcha, "", settings.RateChallengePoWThenCaptcha},
		{"garbage picker falls through", "not-a-mode", settings.RateChallengeCaptchaOnly, settings.RateChallengeCaptchaOnly},
	} {
		t.Run(c.name, func(t *testing.T) {
			var cfg settings.Settings
			cfg.Global.KnownBrowserAction = "pass"
			cfg.Nginx.ChallengeTargets.Extra = []string{"BadBot"}
			cfg.Nginx.ChallengeTargets.DefaultAction = c.defaultAct
			cfg.RateLimit.Default.ChallengeMode = c.rateMode

			// The resolver itself.
			if got := cfg.UABlacklistChain(); got != c.want {
				t.Fatalf("UABlacklistChain()=%q, want %q", got, c.want)
			}
			// Wire 1: the forward-auth decision.
			d, ok := uaDecide(bot, "", cfg, nil)
			if !ok {
				t.Fatal("forward-auth did not challenge a black-listed UA")
			}
			if d.chMode != c.want {
				t.Errorf("forward-auth chMode=%q, want %q", d.chMode, c.want)
			}
			// Wire 2: the CAPTCHA-grade requirement must agree about whether
			// that chain ends in a CAPTCHA -- a grade demanded for a chain
			// that never issues one is a permanent re-challenge.
			wantGrade := c.want == settings.RateChallengeCaptchaOnly ||
				c.want == settings.RateChallengePoWThenCaptcha
			if got := uaRequiresCaptchaGrade(bot, cfg); got != wantGrade {
				t.Errorf("captcha-grade requirement=%v, want %v (chain %s)", got, wantGrade, c.want)
			}
		})
	}
}
