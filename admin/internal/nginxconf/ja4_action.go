package nginxconf

import (
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// ResolveJA4VerdictAction returns the chain (or "deny") the operator configured
// for a JA4 verdict whose action is "bot": the JA4 tab's default, then a
// per-preset override, then the row's own, each winning over the last.  ""
// means nothing was configured and the caller keeps its own base.
//
// THE single resolver for this axis, shared by the nginx render (which needs to
// know which verdicts deny) and the daemon (both its forward-auth decision and
// its challenge serve).  It lives here rather than in handlers because the
// render cannot import that package -- and keeping two copies is what left the
// forward-auth wire ignoring this axis entirely while native honoured it.
func ResolveJA4VerdictAction(verdict string, n settings.Nginx) string {
	if verdict == "" {
		return ""
	}
	out := ""
	if act := strings.TrimSpace(n.JA4Verdicts.DefaultAction); settings.IsValidRateChallengeMode(act) {
		out = act
	}
	if act := ja4PresetAction(verdict, n); settings.IsValidRateChallengeMode(act) {
		out = act
	}
	if act := ja4ExtraAction(verdict, n.JA4Verdicts); settings.IsValidRateChallengeMode(act) {
		out = act
	}
	return out
}

// ChainEndsInCaptcha reports whether a served chain finishes with a CAPTCHA --
// i.e. whether clearing it mints a CAPTCHA-grade pass.  Shared by the render
// (which lists the fingerprints/UAs that demand the grade) and the daemon's
// pass-cookie veto, for the same one-resolver reason as
// ResolveJA4VerdictAction above.
func ChainEndsInCaptcha(chMode string) bool {
	return chMode == settings.RateChallengeCaptchaOnly ||
		chMode == settings.RateChallengePoWThenCaptcha
}

// EffectiveJA4BotChain is ResolveJA4VerdictAction plus the axis's inherit
// fallback: a bot verdict with nothing configured on this tab runs the
// operating default chain (RateLimit.Default.ResolvedChallengeMode --
// pow_then_captcha on a fresh install), exactly what the settings UI shows
// for the unset option.  Inheriting rather than pinning a chain here keeps
// one knob in charge, and the default's proof-of-work leg is deliberate: it
// costs a person nothing, costs a bot fleet real compute, and its funnel
// tells simple no-JS bots (PoW stays zero) apart from JS-capable ones.
//
// THE effective-chain resolver for a bot-verdict fingerprint, used by the
// forward-auth decision (ja4Decide), the challenge serve, the pass-cookie
// grade gate, and the nginx render -- one place, so the chain a client is
// served, the chain the check answers with, and the grade its cookie must
// carry can never disagree (a gate/serve disagreement is a challenge loop;
// ja4Decide's old hardcoded captcha_only vs native's base-default serve was
// exactly such a split).  May return "deny"; deny never ends in a CAPTCHA
// and is dispatched before cookies, so ChainEndsInCaptcha(deny) == false is
// the right reading.
func EffectiveJA4BotChain(verdict string, s settings.Settings) string {
	if act := ResolveJA4VerdictAction(verdict, s.Nginx); act != "" {
		return act
	}
	return s.RateLimit.Default.ResolvedChallengeMode()
}

// ja4PresetAction: the override attached to the preset group that ships the
// verdict, if the operator set one.
func ja4PresetAction(verdict string, n settings.Nginx) string {
	if len(n.JA4Verdicts.PresetAction) == 0 {
		return ""
	}
	for _, g := range JA4VerdictGroups {
		for _, r := range g.Rules {
			if r.Verdict == verdict {
				return strings.TrimSpace(n.JA4Verdicts.PresetAction[g.ID])
			}
		}
	}
	return ""
}

// ja4ExtraAction: the override on the operator's own row carrying this verdict.
// A disabled row has no opinion.
func ja4ExtraAction(verdict string, c settings.JA4VerdictsConfig) string {
	for i, e := range c.Extra {
		if e.Verdict != verdict {
			continue
		}
		if i < len(c.ExtraDisabled) && c.ExtraDisabled[i] {
			continue
		}
		if i < len(c.ExtraAction) {
			return strings.TrimSpace(c.ExtraAction[i])
		}
	}
	return ""
}
