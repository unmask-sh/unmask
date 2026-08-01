package handlers

import (
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// crawlerBadgeChallenged reports whether a crawler-user-agents.json-listed UA
// is one the CURRENT policy deliberately challenges rather than rescues: its
// category resolves to black or none, or its own pattern sits in
// upstream_disabled.  The hunt badge title hangs on this: for a rescued
// crawler, a row in the challenge log means the request failed IP-range
// verification (the spoof signal), but for a deliberately-challenged one the
// genuine crawler lands here too and the title must not claim a failed
// verification.
//
// An enabled SearchBots Extra pattern rescues the UA no matter what the
// upstream config says, mirroring isSearchBotUA's resolution order.
// ChallengeTargets entries are ignored on purpose: an upstream-white crawler
// listed there is still rescued by the search-bot axis (it wins in the
// decision map), so those rows cannot reach the log in the first place.
//
// tag is the UA's primary upstream category (classify.LookupTag); callers that
// already ran LookupCrawler pass it through to avoid a second scan.  Display
// only -- the policy resolves against settings as they are NOW, so rows logged
// under an older config are read under the current one (same trade the UA
// rank's registered-list column already makes).
func crawlerBadgeChallenged(ua, tag string, sb settings.SearchBotsConfig) bool {
	if ua == "" || tag == "" {
		return false
	}
	for i, p := range sb.Extra {
		if i < len(sb.ExtraDisabled) && sb.ExtraDisabled[i] {
			continue
		}
		if matchedRegex(p, ua) {
			return false
		}
	}
	if classify.ResolveGroupMode(tag, sb.UpstreamGroupMode) != classify.GroupModeWhite {
		return true
	}
	for _, p := range sb.UpstreamDisabled {
		if matchedRegex(p, ua) {
			return true
		}
	}
	return false
}

// uaChallengedByUA builds the per-UA lookup behind the events-table partial's
// $.UAChallenged: true for every listed-crawler UA in uas that the current
// policy deliberately challenges.  Rescued crawlers and non-crawlers carry no
// entry, so a template `index` on them yields false and the badge keeps its
// spoof-signal title.
func uaChallengedByUA(uas []string, sb settings.SearchBotsConfig) map[string]bool {
	out := map[string]bool{}
	seen := map[string]bool{}
	for _, ua := range uas {
		if ua == "" || seen[ua] {
			continue
		}
		seen[ua] = true
		c, tag := classify.LookupCrawler(ua)
		if c == "" || c == "other" {
			continue
		}
		if crawlerBadgeChallenged(ua, tag, sb) {
			out[ua] = true
		}
	}
	return out
}
