package nginxconf

import (
	"net"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// IPBypassMatcher tests whether an IP is allowlisted: the enabled bypass-IP
// presets (= Googlebot / Bingbot / GPTBot official ranges, internal LBs) plus
// the operator's enabled bypass_ips rows.
//
// The native path bakes this allowlist into the geo $is_bypass_ip block, but
// the forward-auth path and the community-bans auto-ban guard need to test it
// in Go.  Centralising it here keeps every caller CIDR- and preset-aware so a
// trusted crawler is never challenged or banned regardless of mode.
type IPBypassMatcher struct {
	nets []*net.IPNet
	ips  map[string]bool
}

// NewIPBypassMatcher precompiles the BAN-guard bypass ranges once (= the trusted
// set: presets + bypass_ips, NOT stats_exclude).  It is cheap relative to regex
// compilation, but callers on hot paths should still cache it alongside their
// other per-settings matchers.  For the forward-auth CHALLENGE bypass (which also
// exempts stats_exclude IPs, mirroring native's $is_bypass_ip) use
// NewChallengeBypassMatcher instead.
func NewIPBypassMatcher(n settings.Nginx) *IPBypassMatcher {
	nets, ips := parseBypassRanges(BypassIPCIDRs(n))
	return &IPBypassMatcher{nets: nets, ips: ips}
}

// NewChallengeBypassMatcher precompiles the CHALLENGE bypass ranges (the ban-guard
// set PLUS stats_exclude), so the forward-auth authcheck exempts exactly the IPs
// native's `geo $is_bypass_ip` block does from the challenge.
func NewChallengeBypassMatcher(n settings.Nginx) *IPBypassMatcher {
	nets, ips := parseBypassRanges(ChallengeBypassIPCIDRs(n))
	return &IPBypassMatcher{nets: nets, ips: ips}
}

// Match reports whether ip is allowlisted.  An empty or unparseable ip is never
// a match (= ja4_only feed entries and garbage both fall through).
func (m *IPBypassMatcher) Match(ip string) bool {
	if m == nil || ip == "" {
		return false
	}
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	if m.ips[pip.String()] {
		return true
	}
	for _, nw := range m.nets {
		if nw.Contains(pip) {
			return true
		}
	}
	return false
}

// Empty reports whether the matcher holds no ranges (= bypass disabled).
func (m *IPBypassMatcher) Empty() bool {
	return m == nil || (len(m.nets) == 0 && len(m.ips) == 0)
}

// BypassIPCIDRs is the BAN-guard / trusted allowlist: the enabled bypass presets
// expanded to CIDRs plus the enabled bypass_ips rows (disabled rows skipped).  It
// backs the honeypot/manual auto-ban whitelist and the community-bans guard, so a
// trusted crawler (Googlebot / Bingbot / GPTBot) or an operator bypass IP is
// never auto-banned (CLAUDE.md #4).  It deliberately does NOT include
// stats_exclude_ips: stats exclusion is a dashboard filter, not a ban-policy
// grant -- no RELEASED version ever exempted those from bans (an unreleased
// interim commit briefly did), and folding the
// private-networks preset in here would make the whole RFC1918 space unbannable.
// The forward-auth CHALLENGE bypass, which DOES mirror native's stats-exclude
// exemption, is ChallengeBypassIPCIDRs.
func BypassIPCIDRs(n settings.Nginx) []string {
	out := FlattenBypassPresets(EffectiveBypassIPPresets(n))
	for i, ip := range n.BypassIPs {
		if i < len(n.BypassIPsDisabled) && n.BypassIPsDisabled[i] {
			continue
		}
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// ChallengeBypassIPCIDRs is the CHALLENGE bypass set: BypassIPCIDRs plus the
// stats_exclude list.  The native render folds all of these into `geo
// $is_bypass_ip`, so the forward-auth authcheck must exempt the same set from the
// challenge -- else the two modes derive "bypass IP" from different sets and
// disagree on the same request (a monitoring probe from a stats-exclude IP was
// challenged on forward-auth tool1-sg but passed on the native hosts).  Unlike
// the ban guard, a monitoring probe legitimately wants BOTH stats exclusion and
// challenge bypass; it does not want to become unbannable, which is why the two
// sets differ.
func ChallengeBypassIPCIDRs(n settings.Nginx) []string {
	return append(BypassIPCIDRs(n), statsExcludeList(n)...)
}

func parseBypassRanges(cidrs []string) ([]*net.IPNet, map[string]bool) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	ips := make(map[string]bool)
	for _, c := range cidrs {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			if _, nw, err := net.ParseCIDR(c); err == nil {
				nets = append(nets, nw)
			}
		} else if pip := net.ParseIP(c); pip != nil {
			ips[pip.String()] = true
		}
	}
	return nets, ips
}
