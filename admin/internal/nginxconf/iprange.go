// IP range presets (= bypass_ips presets).
//
// Official IP ranges for search / AI / advertising bots are published as JSON
// by each vendor.  UA alone can be spoofed (= fake Googlebot UA), so we need
// a two-stage rescue that also bypasses by IP.
//
// Each source's JSON is embedded at build time (= release snapshot).  When
// the list changes, either wait for the next unmask release or manually
// re-fetch via the planned `unmask-admin update-iprange` (= ROADMAP).
package nginxconf

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
)

// BypassIPGroup: one source of an official IP range.
//
// Enabled per-group via config.yml's nginx.bypass_ip_enabled_presets (= list
// of IDs to turn ON).  Defaults() ships every group ID in that list so a
// fresh install rescues crawlers out of the box.  IDs are NOT in the same
// namespace as SearchBotGroups (= managed separately).
type BypassIPGroup struct {
	ID      string // stable identifier (= "google-common", "bing", "openai-gptbot", etc.)
	Label   string // UI display name
	Source  string // upstream URL (= "https://developers.google.com/...", for display + auto-update reference)
	File    string // embed file name (= "iprange/<file>.json")
	AddedIn string
	// Populated post-load.  Don't build directly; go through Resolve().
	prefixes []string  // merged list of ipv4 / ipv6 prefixes
	creation time.Time // creationTime from the JSON (= for UI display)
}

// BypassIPGroups: list of bypass-IP preset groups.  Order is UI display order.
//
// Search bots come first because they have outsized SEO impact.  AI bots are
// debatable, but rescued by default (= 403-ing GPTBot etc. removes you from
// ChatGPT search results).
var BypassIPGroups = []BypassIPGroup{
	{
		ID:     "google-common",
		Label:  "Google (Googlebot / common crawler IP ranges)",
		Source: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
		File:   "iprange/googlebot.json",
	},
	{
		ID:     "google-special",
		Label:  "Google (special crawlers like AdsBot / Mediabot / Inspection)",
		Source: "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
		File:   "iprange/special-crawlers.json",
	},
	{
		ID:     "google-user-triggered",
		Label:  "Google (user-triggered fetch = Site Search / Verify-this etc.)",
		Source: "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
		File:   "iprange/user-triggered-fetchers.json",
	},
	{
		ID:     "bing",
		Label:  "Bing (bingbot)",
		Source: "https://www.bing.com/toolbox/bingbot.json",
		File:   "iprange/bingbot.json",
	},
	{
		ID:     "duckduckbot",
		Label:  "DuckDuckGo (DuckDuckBot)",
		Source: "https://duckduckgo.com/duckduckbot.json",
		File:   "iprange/duckduckbot.json",
	},
	{
		ID:     "openai-gptbot",
		Label:  "OpenAI (GPTBot = LLM training crawler)",
		Source: "https://openai.com/gptbot.json",
		File:   "iprange/gptbot.json",
	},
	{
		ID:     "openai-searchbot",
		Label:  "OpenAI (OAI-SearchBot = generates ChatGPT search results)",
		Source: "https://openai.com/searchbot.json",
		File:   "iprange/oai-searchbot.json",
	},
	{
		ID:     "openai-chatgpt-user",
		Label:  "OpenAI (ChatGPT-User = user-triggered fetch)",
		Source: "https://openai.com/chatgpt-user.json",
		File:   "iprange/chatgpt-user.json",
	},
	{
		ID:     "perplexitybot",
		Label:  "Perplexity (PerplexityBot)",
		Source: "https://www.perplexity.com/perplexitybot.json",
		File:   "iprange/perplexitybot.json",
	},
	{
		// Real-user Chrome prefetch traffic transits via *.fetch.tunnel.googlezip.net,
		// hits the origin without running JS, and otherwise loops on the challenge
		// page forever -- blocking degrades LCP for legitimate Chrome users by
		// 20-30% on prefetched navigations.  Official IP list is RFC 8805 geofeed,
		// converted to the same JSON schema as the rest of the presets.
		ID:      "chrome-prefetch-proxy",
		Label:   "Chrome Private Prefetch Proxy (= real-user prefetch via *.fetch.tunnel.googlezip.net)",
		Source:  "https://developer.chrome.com/docs/privacy-security/private-prefetch-proxy-for-network-admins",
		File:    "iprange/chrome-prefetch-proxy.json",
		AddedIn: "v0.1",
	},
}

// iprangePayload: shared JSON schema across vendors.
//
//	{ "creationTime": "...", "prefixes": [{"ipv4Prefix": "..."} or {"ipv6Prefix": "..."}, ...] }
type iprangePayload struct {
	CreationTime string `json:"creationTime"`
	Prefixes     []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

var iprangeOnce sync.Once

// loadAll: parse the embedded JSON for every group at startup.  Failed
// groups remain with empty prefixes (= so the UI can render "load failed"
// via a zero CreationTime()).
func loadAll() {
	iprangeOnce.Do(func() {
		for i := range BypassIPGroups {
			g := &BypassIPGroups[i]
			if g.AddedIn == "" {
				g.AddedIn = "v0.1"
			}
			body, err := assets.IPRange.ReadFile(g.File)
			if err != nil {
				continue
			}
			var p iprangePayload
			if err := json.Unmarshal(body, &p); err != nil {
				continue
			}
			seen := map[string]bool{}
			for _, pre := range p.Prefixes {
				v := pre.IPv4Prefix
				if v == "" {
					v = pre.IPv6Prefix
				}
				if v == "" || seen[v] {
					continue
				}
				seen[v] = true
				g.prefixes = append(g.prefixes, v)
			}
			sort.Strings(g.prefixes)
			// JSON creationTime: format varies subtly per vendor.  Try in order.
			//   - "2026-05-01T14:46:54.000000"          (Google.  Assumed UTC but no Z)
			//   - "2025-02-07T16:56:00.000000"          (Perplexity.  Same shape)
			//   - "2026-04-29T21:03:15.207621"          (chatgpt-user.  Same shape)
			for _, layout := range []string{
				"2006-01-02T15:04:05.000000",
				"2006-01-02T15:04:05.000000Z",
				time.RFC3339Nano,
				time.RFC3339,
			} {
				if t, err := time.Parse(layout, p.CreationTime); err == nil {
					g.creation = t.UTC()
					break
				}
			}
		}
	})
}

// CreationTime: the JSON's creationTime (= used to render "last update YYYY-MM-DD" in the UI).
func (g *BypassIPGroup) CreationTime() time.Time {
	loadAll()
	return g.creation
}

// Prefixes: list of loaded IP prefixes (= read-only).
func (g *BypassIPGroup) Prefixes() []string {
	loadAll()
	return g.prefixes
}

// PrefixCount: for the UI count display.
func (g *BypassIPGroup) PrefixCount() int {
	loadAll()
	return len(g.prefixes)
}

// FlattenBypassPresets: concatenate prefixes from every group listed in
// enabledPresets.  Deduplicated.  Order is by group order → sort order
// within group.  An empty list returns no prefixes (= operator turned every
// preset OFF; UA-only crawler matching takes over as the rescue path).
func FlattenBypassPresets(enabledPresets []string) []string {
	loadAll()
	enabled := map[string]bool{}
	for _, id := range enabledPresets {
		enabled[id] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, g := range BypassIPGroups {
		if !enabled[g.ID] {
			continue
		}
		for _, p := range g.prefixes {
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
