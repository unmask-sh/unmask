package classify

// Per-crawler resolution for the dashboard's AI/crawler-traffic drill-down.
//
// LookupTag classifies a UA into one of the ~11 broad CrawlerTagOrder
// categories via a single joined regex per category (fast).  The stats card
// shows per-category Total/Served, but operators want the breakdown WITHIN a
// category ("search-engine = Googlebot 10000 + Bingbot 5000 ...").  That needs
// the individual crawler identity, which the joined regex discards.
//
// LookupCrawler recovers it with a cheap 2nd stage: take the category from
// LookupTag (one joined-regex pass), then walk only THAT category's individual
// patterns to find which one matched.  The 2nd stage runs only for crawler-
// tagged lines (a fraction of traffic) and inside the async nginxlog
// aggregator, never on the request path -- so the linear walk (bounded by a
// category's pattern count, 252 at most for "seo") is well within budget.

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/assets"
)

type crawlerEntry struct {
	re   *regexp.Regexp
	name string // human-readable name derived from the pattern
}

var (
	crawlerDetailOnce  sync.Once
	crawlerDetailByTag map[string][]crawlerEntry
)

func getCrawlerDetail() map[string][]crawlerEntry {
	crawlerDetailOnce.Do(func() {
		raw := assets.CrawlerUserAgentsJSON
		if path := os.Getenv("UNMASK_CRAWLER_UA_JSON"); path != "" {
			if b, err := os.ReadFile(path); err == nil && len(b) > 1024 {
				raw = b
			}
		}
		crawlerDetailByTag = buildCrawlerDetail(raw)
	})
	return crawlerDetailByTag
}

// buildCrawlerDetail compiles every crawler-user-agents.json pattern
// individually (case-insensitive, matching joinAlt) and groups it under each of
// its tags, preserving JSON order.  Patterns that fail to compile are skipped,
// mirroring joinAlt's tolerance.
func buildCrawlerDetail(jsonRaw []byte) map[string][]crawlerEntry {
	var data []struct {
		Pattern string   `json:"pattern"`
		Tags    []string `json:"tags"`
	}
	if len(jsonRaw) > 0 {
		clean := sanitizeUTF8(jsonRaw)
		_ = json.Unmarshal(clean, &data) // best-effort, mirrors buildCrawlerTagREs
	}
	out := map[string][]crawlerEntry{}
	for _, ent := range data {
		if ent.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(`(?i)(?:` + ent.Pattern + `)`)
		if err != nil {
			continue
		}
		e := crawlerEntry{re: re, name: crawlerDisplayName(ent.Pattern)}
		for _, t := range ent.Tags {
			out[t] = append(out[t], e)
		}
	}
	return out
}

// LookupCrawler returns the individual crawler name and its category for ua.
// Returns ("","") when ua is not a known crawler.  The category equals
// LookupTag(ua); the crawler is the first pattern in that category that ua
// matches.  "other" is a safety fallback that should not occur (the joined
// category regex is the OR of these same patterns).
func LookupCrawler(ua string) (crawler, tag string) {
	if ua == "" {
		return "", ""
	}
	tag = LookupTag(ua)
	if tag == "" {
		return "", ""
	}
	return LookupCrawlerIn(ua, tag), tag
}

// LookupCrawlerIn resolves the individual crawler name within an
// already-known category tag, skipping the LookupTag pass.  Callers that
// already classified the UA (e.g. the nginxlog aggregator, which needs the
// category for crawler_minute anyway) use this to avoid re-running the joined
// category regexes.  Returns the first pattern in tag that ua matches, or
// "other" when none does (a safety fallback -- the joined category regex is
// the OR of these same patterns, so a tag match implies one of them matches).
func LookupCrawlerIn(ua, tag string) string {
	if ua == "" || tag == "" {
		return ""
	}
	for _, e := range getCrawlerDetail()[tag] {
		if e.re.MatchString(ua) {
			return e.name
		}
	}
	return "other"
}

// crawlerDisplayName turns a crawler-user-agents.json regex pattern into a
// readable crawler token: it unescapes backslashes and stops at the first
// regex-construct character, leaving the literal name.
//
//	`Googlebot\/`            -> "Googlebot"
//	`AdsBot-Google([^-]|$)`  -> "AdsBot-Google"
//	`filterdb\.iss\.net\/cr` -> "filterdb.iss.net/cr"
func crawlerDisplayName(pattern string) string {
	const construct = "([{|^$*+?"
	var b []byte
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' && i+1 < len(pattern) {
			i++
			b = append(b, pattern[i]) // the escaped byte, literally
			continue
		}
		stop := false
		for j := 0; j < len(construct); j++ {
			if c == construct[j] {
				stop = true
				break
			}
		}
		if stop {
			break
		}
		b = append(b, c)
	}
	name := strings.Trim(string(b), "/.-_ ")
	if name == "" {
		return "other"
	}
	if len(name) > 48 {
		name = name[:48]
	}
	return name
}
