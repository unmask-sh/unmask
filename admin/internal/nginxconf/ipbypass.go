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

// NewIPBypassMatcher precompiles the bypass ranges once.  It is cheap relative
// to regex compilation, but callers on hot paths should still cache it
// alongside their other per-settings matchers.
func NewIPBypassMatcher(n settings.Nginx) *IPBypassMatcher {
	nets, ips := parseBypassRanges(BypassIPCIDRs(n))
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

// BypassIPCIDRs collects every IP/CIDR that the native `geo $is_bypass_ip` block
// exempts from the challenge, so the forward-auth authcheck's IPBypassMatcher
// mirrors it exactly.  Without a match, native mode lets an IP through while a
// forward-auth host challenges the same IP (a monitoring probe from a
// stats-exclude IP was challenged on forward-auth tool1-sg but passed on the
// native hosts).  The set is: enabled bypass presets expanded to CIDRs, the
// enabled bypass_ips rows (disabled rows skipped), and the stats-exclude list --
// render.go folds all three into $is_bypass_ip (stats-exclude IPs skip the
// challenge too, since a monitoring probe wants both stats exclusion and bypass).
func BypassIPCIDRs(n settings.Nginx) []string {
	out := FlattenBypassPresets(n.BypassIPEnabledPresets)
	for i, ip := range n.BypassIPs {
		if i < len(n.BypassIPsDisabled) && n.BypassIPsDisabled[i] {
			continue
		}
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, ip)
		}
	}
	// stats_exclude_ips (+ the private-networks preset) are folded into
	// $is_bypass_ip by the native render, so they must bypass the challenge in
	// forward-auth mode too — else the two modes derive "bypass IP" from
	// different sets and disagree on the same request.
	out = append(out, statsExcludeList(n)...)
	return out
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
