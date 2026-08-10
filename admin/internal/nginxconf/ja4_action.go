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
