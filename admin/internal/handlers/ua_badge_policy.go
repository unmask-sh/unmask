package handlers

import (
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Badge note kinds for a listed crawler's hunt row.  The three answer the
// operator's real question -- "does this row mean someone is impersonating a
// crawler?" -- and they differ because the enforcement order does.
const (
	// botNoteRange: the vendor publishes egress ranges AND their presets are
	// live, so the bypass-IP veto runs BEFORE the challenge-target decision
	// (see the $final_challenge map: is_bypass_ip is arm 3, is_challenge_target
	// arm 7).  A genuine crawler from those addresses never reaches this log,
	// whatever the UA policy says -- so a row here failed the address check.
	// The strongest spoof signal the badge can carry, and it outranks
	// botNoteChallenged precisely because the IP axis outranks the UA one.
	botNoteRange = "range"
	// botNoteChallenged: no live range rescue, and the policy deliberately
	// challenges this crawler (group black / none, or the pattern disabled).
	// Genuine visits land here too -- nothing was failed.
	botNoteChallenged = "challenged"
	// botNoteListed: rescued by UA today, so a row here is unexplained by
	// policy: the generic "did not verify" reading.
	botNoteListed = "listed"
)

// uaRangeVerified reports whether ua matches a range-backed upstream pattern
// whose bypass-IP presets are currently live.
func uaRangeVerified(ua string, n settings.Nginx) bool {
	for pat := range nginxconf.UARangePresets {
		if matchedRegex(pat, ua) && nginxconf.RangePresetsActive(n, pat) {
			return true
		}
	}
	return false
}

// crawlerBadgeNote resolves which of the three notes a listed crawler's row
// carries.  tag is the UA's primary upstream category (classify.LookupTag);
// callers that already ran LookupCrawler pass it through.  Display only -- it
// resolves against settings as they are NOW, so rows logged under an older
// config are read under the current one (the same trade the UA rank's
// registered-list column already makes).
func crawlerBadgeNote(ua, tag string, n settings.Nginx) string {
	if ua == "" || tag == "" {
		return ""
	}
	if uaRangeVerified(ua, n) {
		return botNoteRange
	}
	if crawlerBadgeChallenged(ua, tag, n.SearchBots) {
		return botNoteChallenged
	}
	return botNoteListed
}

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

// uaBotNoteByUA builds the per-UA lookup behind the events-table partial's
// $.UABotNote: for every listed-crawler UA in uas, which of the three badge
// notes its rows carry.  Non-crawler UAs carry no entry, so a template index
// on them yields "" and the badge falls back to the generic reading.
func uaBotNoteByUA(uas []string, n settings.Nginx) map[string]string {
	out := map[string]string{}
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
		if note := crawlerBadgeNote(ua, tag, n); note != "" {
			out[ua] = note
		}
	}
	return out
}
