package main

import (
	"fmt"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// checkPatternLists: the rows of the rule lists as config.yml holds them.
//
// A pattern carries at most one marker ("contains:", "exact:", "subdomain:")
// before its text.  The settings form puts the marker back at submit time, and
// a value the operator had also typed it into was stored twice:
// "contains:contains:Bot" is a substring match for the literal text
// "contains:Bot", which no request holds.  The form stores one since 0.1.49,
// but a list not saved since keeps its doubled rows, and they read correctly
// at a glance while matching nothing (a large install, 2026-10-06: an
// allowlist row that rescued nothing, a challenge row that challenged
// nothing).
//
// A list's rows and their titles, on/off flags and chains are parallel
// columns, one entry per row.  A column of another length -- a row removed by
// hand without its title, an older version's append -- puts a title, a flag
// or a chain on a row it was not written for.  Titles must match the rows in
// number; the flag and chain columns may stop short (a configuration from
// before they existed reads the missing entries as "on" and "inherit").
func checkPatternLists(s settings.Settings, addOK, addWarn func(t, m string)) {
	n := s.Nginx
	var doubled []string
	look := func(where string, values ...string) {
		for _, v := range values {
			if v != "" && settings.NormalizePattern(v) != v {
				doubled = append(doubled, fmt.Sprintf("%s %q", where, v))
			}
		}
	}
	look("nginx.search_bots.extra", n.SearchBots.Extra...)
	look("nginx.challenge_targets.extra", n.ChallengeTargets.Extra...)
	for _, e := range n.JA4Verdicts.Extra {
		look("nginx.ja4_verdicts.extra", e.Pattern)
	}
	for _, u := range n.Honeypot.URLs {
		look("nginx.honeypot.urls", u.Path)
	}
	for _, p := range n.ProtectedPaths.Paths {
		look("nginx.protected_paths.paths", p.Path)
	}
	for _, p := range n.BypassPaths.Paths {
		look("nginx.bypass_paths.paths", p.Path)
	}
	for _, p := range n.Geo.ExemptPaths {
		look("nginx.geo.exempt_paths", p.Path)
	}
	for _, p := range n.Asn.ExemptPaths {
		look("nginx.asn.exempt_paths", p.Path)
	}
	for _, r := range n.HTTPSRedirectExempt.Rules {
		look("nginx.https_redirect_exempt.rules", r.Pattern)
	}
	look("nginx.admin_allowed_hosts", n.AdminAllowedHosts...)

	var skewed []string
	column := func(list string, rows int, col string, entries int, exact bool) {
		if entries == 0 || entries == rows || (!exact && entries < rows) {
			return
		}
		skewed = append(skewed, fmt.Sprintf("%s has %d row(s) and %d %s", list, rows, entries, col))
	}
	column("nginx.search_bots.extra", len(n.SearchBots.Extra), "extra_title", len(n.SearchBots.ExtraTitle), true)
	column("nginx.search_bots.extra", len(n.SearchBots.Extra), "extra_disabled", len(n.SearchBots.ExtraDisabled), false)
	column("nginx.challenge_targets.extra", len(n.ChallengeTargets.Extra), "extra_title", len(n.ChallengeTargets.ExtraTitle), true)
	column("nginx.challenge_targets.extra", len(n.ChallengeTargets.Extra), "extra_disabled", len(n.ChallengeTargets.ExtraDisabled), false)
	column("nginx.challenge_targets.extra", len(n.ChallengeTargets.Extra), "extra_action", len(n.ChallengeTargets.ExtraAction), false)
	column("nginx.ja4_verdicts.extra", len(n.JA4Verdicts.Extra), "extra_title", len(n.JA4Verdicts.ExtraTitle), true)
	column("nginx.ja4_verdicts.extra", len(n.JA4Verdicts.Extra), "extra_disabled", len(n.JA4Verdicts.ExtraDisabled), false)
	column("nginx.ja4_verdicts.extra", len(n.JA4Verdicts.Extra), "extra_action", len(n.JA4Verdicts.ExtraAction), false)
	column("nginx.bypass_ips", len(n.BypassIPs), "bypass_ips_title", len(n.BypassIPsTitle), true)
	column("nginx.stats_exclude_ips", len(n.StatsExcludeIPs), "stats_exclude_ips_title", len(n.StatsExcludeIPsTitle), true)
	column("nginx.admin_allowed_ips", len(n.AdminAllowedIPs), "admin_allowed_ips_title", len(n.AdminAllowedIPsTitle), true)
	column("nginx.metrics_allow_from", len(n.MetricsAllowFrom), "metrics_allow_from_title", len(n.MetricsAllowFromTitle), true)
	column("nginx.admin_allowed_hosts", len(n.AdminAllowedHosts), "admin_allowed_hosts_title", len(n.AdminAllowedHostsTitle), true)

	if len(doubled) > 0 {
		shown := doubled
		more := ""
		if len(shown) > 5 {
			shown, more = shown[:5], fmt.Sprintf(" (and %d more)", len(doubled)-5)
		}
		addWarn("Rule patterns", fmt.Sprintf("%d pattern(s) carry their marker twice and match nothing they were written for: %s%s. "+
			"Save the settings tab that lists them once -- the form stores a single marker -- or edit config.yml",
			len(doubled), strings.Join(shown, ", "), more))
	}
	if len(skewed) > 0 {
		addWarn("Rule lists", fmt.Sprintf("%s -- a title, flag or chain may sit on a row it was not written for. "+
			"Check each row on its settings tab, put right what belongs elsewhere, and save the tab: it writes every column at the list's length",
			strings.Join(skewed, "; ")))
	}
	if len(doubled) == 0 && len(skewed) == 0 {
		addOK("Rule lists", "every pattern carries at most one marker, and every list's columns line up with its rows")
	}
}
