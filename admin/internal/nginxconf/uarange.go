// uarange.go: which upstream crawler UA patterns are backed by an official,
// machine-readable IP range (= a BypassIPGroups preset).
//
// Rationale: an attacker picks the most-trusted UA to spoof, and the vendors
// whose UAs are most spoofed (Google, Bing, OpenAI, ...) are exactly the ones
// that publish their egress ranges.  For these patterns the UA string is a
// name tag, not an ID: under the standing policy
// (SearchBots.RequireRangeVerification, on unless the operator turns it off)
// they are dropped from the UA whitelist and the rescue rides the vendor's IP
// ranges instead (geo $is_bypass_ip / the forward-auth challenge matcher).  A
// genuine crawler always arrives from a published range, so it still passes;
// a fake UA from outside the ranges falls through to the normal challenge
// flow.
//
// The UA axis and the IP-preset axis are independent (each tab's toggle only
// controls its own rescue path; both ON simply ORs the two paths).  A
// range-backed pattern loses its UA rescue when:
//
//  1. it does not resolve to "white" at all (its group, or the crawler set on
//     its own -- classify.ResolvePatternMode): nothing rescues it by UA, OR
//  2. the policy is on AND every preset backing it is enabled
//     (RangeVerifiedUA).  The presets are required: until the addresses are
//     loaded the policy has nothing to verify against, so the name stands --
//     never "UA dropped AND range off = genuine crawler challenged" by the
//     policy's own hand.
package nginxconf

import (
	"sort"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// googleRangePresets: Google publishes three separate range files (common
// crawlers / special crawlers / user-triggered fetchers) and moves products
// between them; mapping each UA to the union is deliberate.  Narrow per-file
// mapping risks challenging a genuine crawler after such a move — the union
// stays exactly as strong against spoofing (none of the ranges are rentable).
var googleRangePresets = []string{"google-common", "google-special", "google-user-triggered"}

// UARangePresets: upstream crawler-user-agents.json pattern → the
// BypassIPGroups preset IDs whose union covers that vendor's published
// egress.  Keys MUST match the upstream JSON's `pattern` field byte for byte
// (uarange_test.go pins this against the embedded snapshot).
//
// Retired/legacy vendor UAs (Google Web Preview, google-xrawler, ...) are
// listed on purpose: leaving any vendor-branded pattern on UA-only rescue
// keeps a spoof door open ("Googlebot is verified but Google Favicon walks
// through").  Genuine traffic for those UAs no longer exists, so range
// verification simply turns their spoofs into challenges.
var UARangePresets = map[string][]string{
	// Google — current crawlers.
	`Googlebot\/`:                 googleRangePresets,
	`Googlebot-Mobile`:            googleRangePresets,
	`Googlebot-Image`:             googleRangePresets,
	`Googlebot-News`:              googleRangePresets,
	`Googlebot-Video`:             googleRangePresets,
	`Google-InspectionTool`:       googleRangePresets,
	`Storebot-Google`:             googleRangePresets,
	`GoogleOther`:                 googleRangePresets,
	`Google-Extended`:             googleRangePresets,
	`AdsBot-Google([^-]|$)`:       googleRangePresets,
	`AdsBot-Google-Mobile`:        googleRangePresets,
	`Mediapartners-Google`:        googleRangePresets,
	`Mediapartners \(Googlebot\)`: googleRangePresets,
	`APIs-Google`:                 googleRangePresets,
	`Google-Safety`:               googleRangePresets,
	`Google-Ads-Conversions`:      googleRangePresets,
	// Google — user-triggered fetchers.
	`Feedfetcher-Google`:       googleRangePresets,
	`Google-Read-Aloud`:        googleRangePresets,
	`Google-Site-Verification`: googleRangePresets,
	`Google Favicon`:           googleRangePresets,
	// Google — legacy / retired products (see the package comment).
	// AppEngine-Google is special: GAE egress is rentable by anyone, so its
	// UA-only rescue was itself the hole; outside the crawler ranges it now
	// gets challenged like any other client.
	`Google-Adwords-Instant`:                    googleRangePresets,
	`AppEngine-Google`:                          googleRangePresets,
	`Google Web Preview`:                        googleRangePresets,
	`google-xrawler`:                            googleRangePresets,
	`Google-Structured-Data-Testing-Tool`:       googleRangePresets,
	`Google-PhysicalWeb`:                        googleRangePresets,
	`Google-Certificates-Bridge`:                googleRangePresets,
	`developers\.google\.com\/\+\/web\/snippet`: googleRangePresets,

	// Bing.  Microsoft documents bingbot.json as the verification list for
	// its crawler fleet; msnbot is long retired (no genuine traffic).
	`bingbot`:       {"bing"},
	`msnbot`:        {"bing"},
	`BingPreview\/`: {"bing"},

	// DuckDuckGo.  DuckAssistBot publishes its own list (duckassistbot.json),
	// distinct from duckduckbot.json.
	`DuckDuckBot`:             {"duckduckbot"},
	`DuckDuckGo-Favicons-Bot`: {"duckduckbot"},
	`DuckAssistBot`:           {"duckassistbot"},

	// OpenAI — one list per product.
	`GPTBot`:        {"openai-gptbot"},
	`OAI-SearchBot`: {"openai-searchbot"},
	`ChatGPT-User`:  {"openai-chatgpt-user"},

	// Perplexity — PerplexityBot and the user-triggered fetcher publish
	// separate lists.
	`PerplexityBot\/`: {"perplexitybot"},
	`Perplexity-User`: {"perplexity-user"},
	`PerplexityUser`:  {"perplexity-user"},

	// Anthropic — one shared list (claude.com/crawling/bots.json) covers the
	// whole fleet.  Claude-Web and anthropic-ai are retired UA names, listed
	// on purpose (see the package comment): genuine traffic for them no
	// longer exists, so range verification simply turns their spoofs into
	// challenges.
	`[cC]laude[bB]ot`:  {"claude"},
	`Claude-User`:      {"claude"},
	`Claude-SearchBot`: {"claude"},
	`Claude-Web`:       {"claude"},
	`anthropic-ai`:     {"claude"},

	// Apple.  Applebot-Extended is the AI-training opt-out token riding the
	// same fleet.
	`Applebot`:          {"applebot"},
	`Applebot-Extended`: {"applebot"},

	// Amazon.
	`Amazonbot`: {"amazonbot"},
}

// RangePresetsActive reports whether every preset backing pattern is enabled —
// i.e. the vendor's published ranges are actually wired into geo $is_bypass_ip /
// the forward-auth matcher right now.  False for patterns with no published range.
func RangePresetsActive(n settings.Nginx, pattern string) bool {
	ids := UARangePresets[pattern]
	if len(ids) == 0 {
		return false
	}
	// The effective list, not the saved one: an auto-derived preset
	// (autobypass.go) is wired into the geo block / matcher exactly like an
	// explicit one, so the UA resolution must see it too -- that flip from
	// name-rescue to address-verification is the point of deriving it.
	eff := EffectiveBypassIPPresets(n)
	enabled := make(map[string]bool, len(eff))
	for _, id := range eff {
		enabled[id] = true
	}
	for _, id := range ids {
		g := bypassIPGroupByID(id)
		if g == nil || !enabled[id] {
			return false
		}
	}
	return true
}

func bypassIPGroupByID(id string) *BypassIPGroup {
	for i := range BypassIPGroups {
		if BypassIPGroups[i].ID == id {
			return &BypassIPGroups[i]
		}
	}
	return nil
}

// RangeVerifiedUA returns the set of range-backed upstream UA patterns the
// standing policy verifies by address: the policy is on and every preset
// backing the pattern is enabled.  Callers drop these patterns from the UA
// whitelist (native render) / the search_ai pass (forward-auth); whether the
// request still passes is then purely the IP axis's business (bypass-IP
// presets).
//
// A crawler set to "none" or "black" is not in this set: it has no UA rescue
// to replace, and the render and IsBot already keep it off the rescue list
// (collectUpstreamPatternsByMode, UpstreamUnrescued).
func RangeVerifiedUA(n settings.Nginx) map[string]bool {
	out := make(map[string]bool, len(UARangePresets))
	if !n.SearchBots.RangeVerificationRequired() {
		return out
	}
	for pat := range UARangePresets {
		if RangePresetsActive(n, pat) {
			out[pat] = true
		}
	}
	return out
}

// UpstreamUnrescued: the crawlers the operator set one by one to "none" or
// "black", sorted -- the patterns classify.IsBot must not report as a
// rescued search_ai hit (classify.SetUpstreamUnrescued).
func UpstreamUnrescued(n settings.Nginx) []string {
	var out []string
	for pat, mode := range n.SearchBots.UpstreamPatternMode {
		if mode == classify.GroupModeNone || mode == classify.GroupModeBlack {
			out = append(out, pat)
		}
	}
	sort.Strings(out)
	return out
}

// RangeVerifiedPresetIDs returns the preset IDs backing pattern, or nil when
// the pattern has no published range (= stays on UA-only rescue).  For the
// settings UI's per-pattern "verified by IP range" badge.
func RangeVerifiedPresetIDs(pattern string) []string {
	return UARangePresets[pattern]
}

// UpstreamRangeActive reports, per range-backed pattern, whether the vendor's
// published addresses are loaded right now — the settings UI's badge, green
// when they are.
//
// Deliberately absolute: it answers "can this bot be verified by address at
// all", and nothing about how the row is set.  An earlier version folded both
// in (green only when the row also had its UA rescue off), which left the
// badge changing colour for two unrelated reasons and a legend that could not
// describe either without contradicting the policy switch.  What a bot with a
// green badge does is read off the switch and the row's own setting, each of
// which says one thing.
func UpstreamRangeActive(n settings.Nginx) map[string]bool {
	out := make(map[string]bool, len(UARangePresets))
	for pat := range UARangePresets {
		out[pat] = RangePresetsActive(n, pat)
	}
	return out
}

// SortedRangeVerifiedUA: RangeVerifiedUA as a sorted slice, for
// deterministic joins (regex alternation, rendered comments).
func SortedRangeVerifiedUA(n settings.Nginx) []string {
	set := RangeVerifiedUA(n)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
