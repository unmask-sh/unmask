package handlers

import (
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// uaRequiresCaptchaGrade reports whether the operator's rules put this UA on a
// chain that ends in a CAPTCHA -- captcha_only, or pow_then_captcha, whose
// proof-of-work leg issues no cookie at all and hands off to the CAPTCHA.
//
// Why the question is worth asking of a client that already holds a pass:
// clearing a chain that ends in a CAPTCHA mints a CAPTCHA-grade cookie, so an
// ordinary visitor on such a rule is unaffected by anything gated on this.
// What is affected is a client holding a proof-of-work cookie it obtained
// some other way -- and "some other way" is a real, measured thing: a crawler
// read the challenge page, solved the 16-bit proof-of-work in its own code
// (never running our JavaScript, which is why the load counter stayed at 1 for
// a week), minted the cookie itself and served itself 137,051 requests a day
// through a rule that said CAPTCHA.
//
// The rule's own action wins over the list default, exactly as the render side
// resolves it.  An unlisted UA requires nothing: the operator has said nothing
// about it, and the Operating-mode buckets decide its posture.
func uaRequiresCaptchaGrade(ua string, cfg settings.Settings) bool {
	if ua == "" {
		return false
	}
	listed, category, action := lookupUAListed(ua, cfg.Nginx)
	if listed == "" || category != "challenge" {
		return false
	}
	act := strings.TrimSpace(action)
	if act == "" {
		// A listed row with no action of its own inherits the black-list
		// chain, through the resolver both wires decide with.
		act = cfg.UABlacklistChain()
	}
	return act == settings.RateChallengeCaptchaOnly || act == settings.RateChallengePoWThenCaptcha
}

// requestNeedsCaptchaGrade reports whether THIS request must be backed by a
// CAPTCHA-grade cookie to pass, folding the two independent sources of a CAPTCHA
// requirement:
//
//   - the UA sits on a challenge-target chain that ends in a CAPTCHA
//     (uaRequiresCaptchaGrade), and/or
//   - the URI hits a protected path whose mode ends in a CAPTCHA
//     (captcha / pow_then_captcha).
//
// This is the forward-auth twin of native's $unmask_needs_captcha_grade map: a
// proof-of-work cookie must not satisfy a CAPTCHA gate on EITHER wire.  Before
// this, the forward-auth pass-cookie veto only consulted the UA source, so a
// PoW cookie sailed through a captcha-graded protected path (e.g. the admin
// login gate) — the hole this closes.
func requestNeedsCaptchaGrade(ua, uri, site string, cfg settings.Settings) bool {
	if uaRequiresCaptchaGrade(ua, cfg) {
		return true
	}
	return nginxconf.ModeEndsInCaptcha(protectedModeForOrig(cfg.Nginx, site, uri))
}

// gradeSatisfies reports whether a credential of grade `have` meets a CAPTCHA
// requirement.
//
// Only a genuine CAPTCHA solve does.  A re-bound credential is deliberately
// excluded even though it descends from one: the re-bind is what carries a
// solve onto addresses that never solved anything, and letting it satisfy the
// requirement would leave the exact hole this closes -- one CAPTCHA, then a
// fleet.  The lineage's own grade is checked separately on that path, so a
// roaming person who really did clear a CAPTCHA is still re-bound silently.
func gradeSatisfies(have string) bool {
	return have == "captcha"
}
