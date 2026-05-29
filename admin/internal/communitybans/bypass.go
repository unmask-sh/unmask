package communitybans

import (
	"net"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// BypassMatcher tests whether an IP falls inside a bypass range -- the enabled
// bypass presets (= Googlebot / Bingbot / GPTBot official ranges, internal LBs)
// plus the operator's own enabled bypass_ips rows.
//
// Why community-bans needs this: the challenge path already exempts
// $is_bypass_ip (= Googlebot accident prevention), but the auto-ban path writes
// into the local ban file, which the native plugin reads with no bypass
// awareness.  A community report on a search-engine IP would therefore lock it
// to CAPTCHA.  The matcher lets pull strip such entries before enforcement and
// lets the browse view flag them as exempt.
type BypassMatcher struct {
	nets []*net.IPNet
	ips  map[string]bool
}

// NewBypassMatcher precompiles the bypass ranges from settings once so a single
// pull / render pass can test every entry without re-parsing.
func NewBypassMatcher(s settings.Settings) *BypassMatcher {
	nets, ips := parseBypassRanges(enforceableBypassCIDRs(s))
	return &BypassMatcher{nets: nets, ips: ips}
}

// Match reports whether ip is whitelisted.  An empty ip is never a match (=
// ja4_only entries can't be tested against an IP range).
func (m *BypassMatcher) Match(ip string) bool {
	if m == nil || ip == "" {
		return false
	}
	return ipInBypass(ip, m.nets, m.ips)
}

// enforceableBypassCIDRs collects the bypass ranges that shield a feed entry
// from enforcement: every CIDR/IP from the enabled bypass presets plus the
// operator's own enabled bypass_ips rows (disabled rows are skipped).
func enforceableBypassCIDRs(s settings.Settings) []string {
	out := nginxconf.FlattenBypassPresets(s.Nginx.BypassIPEnabledPresets)
	for i, ip := range s.Nginx.BypassIPs {
		if i < len(s.Nginx.BypassIPsDisabled) && s.Nginx.BypassIPsDisabled[i] {
			continue
		}
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// excludeBypassedEntries returns the entries whose IP is NOT whitelisted, plus
// the count removed.  Entries without an IP (= ja4_only) are kept -- a
// fingerprint can't be matched against an IP range, so they fall through to
// map-only enforcement, which $is_bypass_ip already exempts.
func excludeBypassedEntries(entries []FeedEntry, m *BypassMatcher) ([]FeedEntry, int) {
	if m == nil || (len(m.nets) == 0 && len(m.ips) == 0) {
		return entries, 0
	}
	kept := make([]FeedEntry, 0, len(entries))
	skipped := 0
	for _, e := range entries {
		if m.Match(e.IP) {
			skipped++
			continue
		}
		kept = append(kept, e)
	}
	return kept, skipped
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

func ipInBypass(ip string, nets []*net.IPNet, ips map[string]bool) bool {
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	if ips[pip.String()] {
		return true
	}
	for _, nw := range nets {
		if nw.Contains(pip) {
			return true
		}
	}
	return false
}
