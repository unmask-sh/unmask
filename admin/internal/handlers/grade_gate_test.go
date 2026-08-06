package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Which UAs carry a CAPTCHA requirement, and what satisfies it.
//
// The requirement only bites a client holding a pass it earned some other way:
// clearing a chain that ends in a CAPTCHA issues a CAPTCHA-grade cookie -- the
// proof-of-work leg issues none and hands off -- so an ordinary visitor on
// such a rule already carries one.
func TestUARequiresCaptchaGrade(t *testing.T) {
	cfg := func(action string) settings.Settings {
		var s settings.Settings
		s.Nginx.ChallengeTargets.Extra = []string{"contains:SomeBot"}
		s.Nginx.ChallengeTargets.ExtraAction = []string{action}
		return s
	}
	const ua = "Mozilla/5.0 (compatible; SomeBot/1.0)"

	for _, c := range []struct {
		action string
		want   bool
	}{
		{"", true},
		{settings.RateChallengeCaptchaOnly, true},
		{settings.RateChallengePoWThenCaptcha, true},
		{settings.RateChallengePoWOnly, false},
		{settings.RateChallengeDeny, false},
	} {
		if got := uaRequiresCaptchaGrade(ua, cfg(c.action)); got != c.want {
			t.Errorf("action %q -> %v, want %v", c.action, got, c.want)
		}
	}

	// A UA the operator never listed carries no requirement: they have said
	// nothing about it, and the Operating-mode buckets decide its posture.
	if uaRequiresCaptchaGrade("Mozilla/5.0 (Macintosh) Safari/605", cfg("")) {
		t.Error("an unlisted UA must not inherit a listed rule's requirement")
	}
	if uaRequiresCaptchaGrade("", cfg("")) {
		t.Error("no UA at all cannot match a UA rule")
	}
}

// Only a genuine CAPTCHA solve satisfies a CAPTCHA requirement.
//
// A re-bound credential is excluded even though it descends from a solve: the
// re-bind is the mechanism that carries one solve onto addresses that never
// solved anything, so honouring it here would leave the hole open -- one
// CAPTCHA, then a fleet.  A person who really did clear one still roams, via
// the lineage's own grade on the rebind path.
func TestGradeSatisfies(t *testing.T) {
	for kind, want := range map[string]bool{
		"captcha": true,
		"pow":     false,
		"rebind":  false,
		"":        false,
		"passkey": false,
	} {
		if got := gradeSatisfies(kind); got != want {
			t.Errorf("gradeSatisfies(%q) = %v, want %v", kind, got, want)
		}
	}
}
