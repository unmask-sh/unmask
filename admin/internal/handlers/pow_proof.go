package handlers

import (
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// chainTerms reads a served chain (the ct carries it, captcha.Binding.Chain)
// as the terms of its CAPTCHA leg: the grade of pass clearing the CAPTCHA
// earns, and whether a proof-of-work had to be solved first.
//
//   - captcha_only: the operator put the CAPTCHA first on purpose (a rate
//     limit, a protected path, a rule that says so), so nothing is owed
//     before it and clearing it is a CAPTCHA-grade pass.
//   - pow_then_captcha: the proof-of-work leg ran first and is owed; the
//     pass is CAPTCHA-grade.  Without the proof the CAPTCHA leg was
//     answerable on its own, which made the built-in CAPTCHA's pass the
//     cheapest credential on the site: a page fetch and one POST.
//   - pow_only: the page shows the CAPTCHA only to a client it flagged on
//     its own (the automation tells, after two retries), after the
//     proof-of-work it owes anyway, and what it earns is what the posture
//     asked for -- a proof-of-work pass, never a CAPTCHA-grade one off a
//     page that demanded no CAPTCHA.
//
// Anything else (a chain that serves no page, a token from before the chain
// was signed) is not a chain this verify answers for.
func chainTerms(chain string) (grade string, needPow, ok bool) {
	switch chain {
	case settings.RateChallengeCaptchaOnly:
		return "captcha", false, true
	case settings.RateChallengePoWThenCaptcha:
		return "captcha", true, true
	case settings.RateChallengePoWOnly:
		return "pow", true, true
	}
	return "", false, false
}

// powProofEntriesMax is how many entries of a _bv list are read for the
// proof: the verifiers' own cap on the list.
const powProofEntriesMax = 16

// powProofFor reports whether the request shows the proof-of-work the page
// served at issued owed: a "<issued>.pow2.<nonce>.<flags>" entry that
// verifies for the client the way the plugin verifies the cookie -- the
// seed of this bind key, host and second, at the site's difficulty -- taken
// from the verify's own field first, then from any _bv entry the request
// carries.  The seed is derived from the second the page was served, which
// is the second the ct carries, so a proof of an earlier page, or of this
// client's page on another host, does not answer for this one.
func (h *Handler) powProofFor(r *http.Request, proof string, issued int64, bindKey, host, site string) bool {
	cfg := h.cfg()
	ch := cfg.Challenge.Resolve(site)
	pow, cap, diff := ch.PowCookieValidSecondsResolved(), ch.CaptchaCookieValidSecondsResolved(), ch.ResolvedPowDifficulty()
	check := func(entry string) bool {
		entry = strings.TrimSpace(entry)
		if entry == "" || len(entry) > 128 {
			return false
		}
		_, kind, at, ok := cookies.MatchingEntry(entry, cfg.Secret.BVSecret, bindKey, host, pow, cap, diff)
		return ok && kind == "pow2" && at == issued
	}
	if check(proof) {
		return true
	}
	for _, c := range r.Cookies() {
		if c.Name != "_bv" || c.Value == "" || len(c.Value) > 1024 {
			continue
		}
		for i, entry := range strings.Split(c.Value, "~") {
			if i >= powProofEntriesMax {
				break
			}
			if check(entry) {
				return true
			}
		}
	}
	return false
}
