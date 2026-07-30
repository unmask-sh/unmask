// uarange.go: which upstream crawler UA patterns are backed by an official,
// machine-readable IP range (= a BypassIPGroups preset).
//
// Rationale: an attacker picks the most-trusted UA to spoof, and the vendors
// whose UAs are most spoofed (Google, Bing, OpenAI, ...) are exactly the ones
// that publish their egress ranges.  For these patterns the UA string is a
// name tag, not an ID: the default drops them from the UA whitelist and lets
// the rescue ride the vendor's IP ranges instead (geo $is_bypass_ip / the
// forward-auth challenge matcher).  A genuine crawler always arrives from a
// published range, so it still passes; a fake UA from outside the ranges
// falls through to the normal challenge flow.
//
// The UA axis and the IP-preset axis are independent (each tab's toggle only
// controls its own rescue path; both ON simply ORs the two paths).  The
// per-pattern UA state resolves as:
//
//  1. listed in SearchBots.UpstreamDisabled  -> UA rescue OFF (explicit)
//  2. listed in SearchBots.UpstreamUAEnabled -> UA rescue ON  (explicit;
//     the operator accepts that a spoofed UA passes too)
//  3. neither (auto) -> OFF while every backing preset is enabled and past
//     the SeenVersion NEW gate, ON otherwise.  The auto rule keeps two
//     installs safe without a config migration: a pre-v0.1.7 upgrade (and a
//     preset an operator keeps off) stays on UA-only rescue -- never "UA
//     dropped AND range off = genuine crawler challenged" -- and a current
//     install gets IP-verification by default.  Saving the UA-filter tab
//     writes the shown state into the explicit lists, after which the IP
//     tab no longer influences this axis.
package nginxconf

import (
	"sort"

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

	// Apple.  Applebot-Extended is the AI-training opt-out token riding the
	// same fleet.
	`Applebot`:          {"applebot"},
	`Applebot-Extended`: {"applebot"},

	// Amazon.
	`Amazonbot`: {"amazonbot"},
}

// RangePresetsActive reports whether every preset backing pattern is enabled
// and past the SeenVersion NEW gate — i.e. the vendor's published ranges are
// actually wired into geo $is_bypass_ip / the forward-auth matcher right now.
// False for patterns with no published range.
func RangePresetsActive(n settings.Nginx, pattern string) bool {
	ids := UARangePresets[pattern]
	if len(ids) == 0 {
		return false
	}
	enabled := make(map[string]bool, len(n.BypassIPEnabledPresets))
	for _, id := range n.BypassIPEnabledPresets {
		enabled[id] = true
	}
	for _, id := range ids {
		g := bypassIPGroupByID(id)
		if g == nil || !enabled[id] || PresetIsNew(n.SeenVersion, g.AddedIn) {
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

// EffectiveUpstreamUAOff returns the set of range-backed upstream UA patterns
// whose UA-string rescue is effectively off under the given settings (see the
// package comment for the explicit-lists-then-auto resolution).  Callers drop
// these patterns from the UA whitelist (native render) / the search_ai pass
// (forward-auth); whether the request still passes is then purely the IP
// axis's business (bypass-IP presets).
func EffectiveUpstreamUAOff(n settings.Nginx) map[string]bool {
	disabled := make(map[string]bool, len(n.SearchBots.UpstreamDisabled))
	for _, p := range n.SearchBots.UpstreamDisabled {
		disabled[p] = true
	}
	uaEnabled := make(map[string]bool, len(n.SearchBots.UpstreamUAEnabled))
	for _, p := range n.SearchBots.UpstreamUAEnabled {
		uaEnabled[p] = true
	}
	out := make(map[string]bool, len(UARangePresets))
	for pat := range UARangePresets {
		switch {
		// Standing policy wins over every per-pattern state, including an
		// explicit UA opt-in: the operator turned it on precisely to stop
		// vendor-branded UAs passing on the strength of the string, and a
		// row saved months earlier should not quietly carve an exception
		// out of it.  Turning the policy back off restores the per-pattern
		// states below untouched -- they are still in the config.
		//
		// RangePresetsActive is required, not incidental: dropping the UA
		// while the vendor's ranges are NOT wired in (preset off, or still
		// behind the NEW gate) leaves the crawler with no rescue path at
		// all, and a genuine Googlebot gets challenged.  The policy is
		// "verify by address instead of by name" -- with no addresses
		// loaded there is nothing to verify against, so the name stands.
		case n.SearchBots.RangeVerificationRequired() && RangePresetsActive(n, pat):
			out[pat] = true
		case disabled[pat]:
			out[pat] = true
		case uaEnabled[pat]:
			// explicit UA-only opt-in
		case RangePresetsActive(n, pat):
			out[pat] = true
		}
	}
	return out
}

// RangeVerifiedPresetIDs returns the preset IDs backing pattern, or nil when
// the pattern has no published range (= stays on UA-only rescue).  For the
// settings UI's per-pattern "verified by IP range" badge.
func RangeVerifiedPresetIDs(pattern string) []string {
	return UARangePresets[pattern]
}

// UpstreamRVStates classifies every range-backed pattern for the settings
// UI's badge: which of the two independent rescue paths (UA string / vendor
// IP range) are live for it right now.
//
//	"ip"   — UA off, ranges active: genuine crawler passes by IP, spoof challenged
//	"or"   — UA on,  ranges active: passes by either (spoofed UA passes too)
//	"ua"   — UA on,  ranges inactive: UA-string rescue only
//	"none" — UA off, ranges inactive: no rescue; a genuine crawler is
//	         challenged (reachable only via explicit choices — auto never
//	         resolves here)
func UpstreamRVStates(n settings.Nginx) map[string]string {
	uaOff := EffectiveUpstreamUAOff(n)
	out := make(map[string]string, len(UARangePresets))
	for pat := range UARangePresets {
		active := RangePresetsActive(n, pat)
		switch {
		case uaOff[pat] && active:
			out[pat] = "ip"
		case active:
			out[pat] = "or"
		case uaOff[pat]:
			out[pat] = "none"
		default:
			out[pat] = "ua"
		}
	}
	return out
}

// SortedUpstreamUAOff: EffectiveUpstreamUAOff as a sorted slice, for
// deterministic joins (regex alternation, rendered comments).
func SortedUpstreamUAOff(n settings.Nginx) []string {
	set := EffectiveUpstreamUAOff(n)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
