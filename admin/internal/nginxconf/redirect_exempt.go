// HTTPS-redirect exemptions (= requests that must not be 301'd when
// nginx.https_redirect is on).
//
// The redirect fires at the very top of the rendered server.inc, before any
// gate.  Two classes of request must never be redirected there:
//
//   - ACME HTTP-01 (path /.well-known/acme-challenge/): a 301 breaks webroot
//     certbot renewals, noticed only on cert-expiry day.
//   - Load-balancer / orchestrator health checks (user-agent): a 301 is a
//     FAILED health check, so the LB drops the node from rotation and its
//     traffic silently stops.  These probes reach the backend directly without
//     X-Forwarded-Proto (GCP/AWS/k8s send proxy headers = NONE by default), so
//     $unmask_forwarded_proto falls back to $scheme=http and the redirect
//     fires on them.  The stable signal is the user-agent, not the path (the
//     health-check path is operator-configured and varies), so this axis
//     matches $http_user_agent rather than $request_uri.
//
// Same preset/deviation model as bypass paths: a missing exemption is the
// dangerous state, so a default-on exemption applies immediately on upgrade.
package nginxconf

// RedirectExemptGroup: a preset group of redirect exemptions.  MatchType picks
// the axis every pattern in the group tests.
type RedirectExemptGroup struct {
	ID        string
	Label     string
	MatchType string // "path" | "ua"
	Patterns  []string
	DefaultOn bool
	AddedIn   string
}

// RedirectExemptMatchPath / MatchUA name the two match axes shared by presets
// and custom rules.
const (
	RedirectExemptMatchPath = "path"
	RedirectExemptMatchUA   = "ua"
)

// RedirectExemptPresetGroups: the shipped exemption presets.  Both default on —
// redirecting an ACME probe or a health check is never intended and breaks the
// machine access silently.
var RedirectExemptPresetGroups = []RedirectExemptGroup{
	{
		ID:        "acme",
		DefaultOn: true, // a 301'd ACME HTTP-01 = failed cert renewal
		Label:     "ACME HTTP-01 (= /.well-known/acme-challenge/ — webroot cert renewal)",
		MatchType: RedirectExemptMatchPath,
		Patterns:  []string{`^/\.well-known/acme-challenge/`},
	},
	{
		ID:        "lb-health",
		DefaultOn: true, // a 301'd health check = LB drops the node from rotation
		Label:     "Load-balancer health checks (= GoogleHC / ELB-HealthChecker / kube-probe / Azure — matched by user-agent)",
		MatchType: RedirectExemptMatchUA,
		// One pattern (an alternation) so the render emits a single `if`.  These
		// are the health-probe user-agents that hit the backend directly (no
		// X-Forwarded-Proto), i.e. exactly the ones the redirect would 301.
		Patterns: []string{`^(GoogleHC|ELB-HealthChecker|kube-probe|Edgio-HealthCheck|AzureHealthCheckAgent)`},
	},
}

// EffectiveRedirectExemptPresets resolves which preset groups are active from
// the operator's recorded deviations.  A group is active when explicitly
// enabled, or DefaultOn and not explicitly disabled.  Unknown IDs are ignored.
func EffectiveRedirectExemptPresets(enabled, disabled []string) map[string]bool {
	en := toSet(enabled)
	dis := toSet(disabled)
	on := make(map[string]bool, len(RedirectExemptPresetGroups))
	for _, g := range RedirectExemptPresetGroups {
		on[g.ID] = en[g.ID] || (g.DefaultOn && !dis[g.ID])
	}
	return on
}

// RedirectExemptClause: one rendered exemption (= one nginx `if ... break`).
type RedirectExemptClause struct {
	MatchType string // "path" | "ua"
	Pattern   string
}

// CustomExemptRule is the minimal shape ResolveRedirectExemptClauses needs from
// a settings.HTTPSRedirectExemptRule, kept package-local so nginxconf does not
// import settings (render.go adapts settings rows into this).
type CustomExemptRule struct {
	Type     string // "path" | "ua"
	Pattern  string
	Disabled bool
}

// ResolveRedirectExemptClauses returns the ordered exemption clauses to render
// before the 301: active presets first (in preset order), then enabled custom
// rules (in operator order).  Empty patterns and disabled custom rows are
// dropped.
func ResolveRedirectExemptClauses(enabledPresets, disabledPresets []string, rules []CustomExemptRule) []RedirectExemptClause {
	active := EffectiveRedirectExemptPresets(enabledPresets, disabledPresets)
	out := make([]RedirectExemptClause, 0, len(RedirectExemptPresetGroups)+len(rules))
	for _, g := range RedirectExemptPresetGroups {
		if !active[g.ID] {
			continue
		}
		for _, p := range g.Patterns {
			if p == "" {
				continue
			}
			out = append(out, RedirectExemptClause{MatchType: g.MatchType, Pattern: p})
		}
	}
	for _, r := range rules {
		if r.Disabled || r.Pattern == "" {
			continue
		}
		mt := r.Type
		if mt != RedirectExemptMatchUA {
			mt = RedirectExemptMatchPath // default/unknown -> path
		}
		out = append(out, RedirectExemptClause{MatchType: mt, Pattern: r.Pattern})
	}
	return out
}
