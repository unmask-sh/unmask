package settings

import "testing"

// The unset action runs the chain, not the CAPTCHA alone.  Both end in a
// CAPTCHA -- same clients stopped, same pass grade demanded -- so the choice
// is about what the operator can see afterwards: the proof-of-work leg splits
// "could not run the JavaScript at all" from "ran it and then abandoned the
// CAPTCHA", which is exactly the distinction this axis exists to draw.
func TestHeaderIntegrityUnsetRunsTheChain(t *testing.T) {
	var g GlobalConfig
	if got := g.HeaderIntegrityResolvedAction(); got != RateChallengePoWThenCaptcha {
		t.Errorf("unset action = %q, want %q", got, RateChallengePoWThenCaptcha)
	}
	// An explicit choice still wins, including the older captcha_only.
	for _, want := range []string{RateChallengePoWOnly, RateChallengeCaptchaOnly, RateChallengePoWThenCaptcha} {
		g.HeaderIntegrityAction = want
		if got := g.HeaderIntegrityResolvedAction(); got != want {
			t.Errorf("explicit %q resolved to %q", want, got)
		}
	}
	// deny is structurally impossible here: a stripped header is a legitimate
	// state, so a misclassified person must always have a chain to clear.
	g.HeaderIntegrityAction = RateChallengeDeny
	if got := g.HeaderIntegrityResolvedAction(); got != RateChallengePoWThenCaptcha {
		t.Errorf("stored deny resolved to %q, want the chain", got)
	}
}

// The stale-browser tier follows the same reasoning: both defaults end in a
// CAPTCHA, and the proof-of-work leg is what tells a client that cannot run
// the JavaScript apart from one that solves the work and abandons the CAPTCHA
// -- the PoW-solving scraper this tier was built for.
func TestStaleBrowserUnsetRunsTheChain(t *testing.T) {
	var g GlobalConfig
	if got := g.StaleBrowserResolvedAction(); got != RateChallengePoWThenCaptcha {
		t.Errorf("unset action = %q, want %q", got, RateChallengePoWThenCaptcha)
	}
	// Unlike header-integrity, this tier may deny: an operator who decides a
	// frozen build is never a person can say so.
	for _, want := range []string{RateChallengePoWOnly, RateChallengeCaptchaOnly, RateChallengePoWThenCaptcha, RateChallengeDeny} {
		g.StaleBrowserAction = want
		if got := g.StaleBrowserResolvedAction(); got != want {
			t.Errorf("explicit %q resolved to %q", want, got)
		}
	}
}

// Every axis that resolves an unset action lands on the same chain.  The point
// is not that pow_then_captcha is right for each in isolation -- it is that an
// operator reading a config should not have to remember which tier is the
// exception.  A tier that wants to drop the proof-of-work leg says so.
func TestUnsetActionsAgreeAcrossAxes(t *testing.T) {
	var s Settings
	got := map[string]string{
		"header_integrity": s.Global.HeaderIntegrityResolvedAction(),
		"stale_browser":    s.Global.StaleBrowserResolvedAction(),
		"manual_ban":       s.Nginx.Bans.ResolveAction("manual", ""),
		"community_bans":   s.CommunityBans.ResolvedAction(),
	}
	for axis, chain := range got {
		if chain != RateChallengePoWThenCaptcha {
			t.Errorf("%s unset -> %q, want %q", axis, chain, RateChallengePoWThenCaptcha)
		}
	}
	// The honeypot tier already agreed; keep it that way.
	if h := s.Nginx.Bans.ResolveAction("honeypot", ""); h != RateChallengePoWThenCaptcha {
		t.Errorf("honeypot unset -> %q, want %q", h, RateChallengePoWThenCaptcha)
	}
}
