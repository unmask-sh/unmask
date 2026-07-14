package communitybans

import (
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// NewBypassMatcher builds the allowlist tester for a settings snapshot.  It is
// the community-bans entry point onto the shared nginxconf.IPBypassMatcher, using
// the BAN-guard set (preset + CIDR + bypass_ips, via NewIPBypassMatcher) -- NOT
// the wider challenge set.  A stats_exclude IP is exempt from the CHALLENGE but
// must still be enforceable by a community-ban feed, so only the operator's
// trusted bypass_ips / crawler presets skip enforcement here.
func NewBypassMatcher(s settings.Settings) *nginxconf.IPBypassMatcher {
	return nginxconf.NewIPBypassMatcher(s.Nginx)
}

// excludeBypassedEntries returns the entries whose IP is NOT allowlisted, plus
// the count removed.  Entries without an IP (= ja4_only) are kept -- a
// fingerprint can't be matched against an IP range, so they fall through to
// map-only enforcement, which $is_bypass_ip already exempts.
func excludeBypassedEntries(entries []FeedEntry, m *nginxconf.IPBypassMatcher) ([]FeedEntry, int) {
	if m.Empty() {
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
