// uarange.go: which upstream crawler UA patterns are backed by an official,
// machine-readable IP range (= a BypassIPGroups preset).
//
// Rationale: an attacker picks the most-trusted UA to spoof, and the vendors
// whose UAs are most spoofed (Google, Bing, OpenAI, ...) are exactly the ones
// that publish their egress ranges.  So for these patterns UA-only rescue is
// inverted: the pattern is dropped from the UA whitelist and the rescue rides
// on the vendor's IP ranges instead (geo $is_bypass_ip / the forward-auth
// challenge matcher).  A genuine crawler always arrives from a published
// range, so it still passes; a fake UA from outside the ranges falls through
// to the normal challenge flow.
//
// Fallback contract (footgun guard): the inversion only applies to a pattern
// when EVERY preset in its list is enabled AND past the SeenVersion NEW gate.
// An operator who turns a range preset off gets UA-only rescue back for that
// vendor — never "UA required AND range off = genuine crawler challenged".
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

// EffectiveRangeVerifiedPatterns returns the set of upstream UA patterns
// whose UA-only rescue is replaced by IP-range verification under the given
// settings: every preset in the pattern's list is enabled and past the
// SeenVersion NEW gate.  Callers drop these patterns from the UA whitelist
// (native render) / the search_ai pass (forward-auth) — the enabled range
// presets then carry the rescue.
func EffectiveRangeVerifiedPatterns(n settings.Nginx) map[string]bool {
	enabled := make(map[string]bool, len(n.BypassIPEnabledPresets))
	for _, id := range n.BypassIPEnabledPresets {
		enabled[id] = true
	}
	byID := make(map[string]*BypassIPGroup, len(BypassIPGroups))
	for i := range BypassIPGroups {
		byID[BypassIPGroups[i].ID] = &BypassIPGroups[i]
	}
	out := make(map[string]bool, len(UARangePresets))
	for pat, ids := range UARangePresets {
		all := len(ids) > 0
		for _, id := range ids {
			g := byID[id]
			if g == nil || !enabled[id] || PresetIsNew(n.SeenVersion, g.AddedIn) {
				all = false
				break
			}
		}
		if all {
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

// SortedRangeVerifiedPatterns: EffectiveRangeVerifiedPatterns as a sorted
// slice, for deterministic joins (regex alternation, rendered comments).
func SortedRangeVerifiedPatterns(n settings.Nginx) []string {
	set := EffectiveRangeVerifiedPatterns(n)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
