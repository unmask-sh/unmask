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
// readable crawler token.  It walks the pattern left-to-right, unescaping
// backslashes and resolving the handful of regex constructs these patterns use
// for case-insensitive matching (anchors, simple character classes, leading
// groups) so a name still falls out -- otherwise common crawlers whose pattern
// happens to start with a construct (e.g. ClaudeBot = `[cC]laude[bB]ot`) would
// all collapse onto "other".
//
//	`Googlebot\/`            -> "Googlebot"
//	`AdsBot-Google([^-]|$)`  -> "AdsBot-Google"   (trailing group is a qualifier)
//	`[cC]laude[bB]ot`        -> "ClaudeBot"        (case-variant char classes)
//	`[pP]ingdom`             -> "Pingdom"
//	`^BW\/`                  -> "BW"               (leading anchor skipped)
//	`(^| )sentry\/`          -> "sentry"           (leading anchor-only group skipped)
func crawlerDisplayName(pattern string) string {
	var b []byte
	i, n := 0, len(pattern)
	for i < n {
		c := pattern[i]
		switch {
		case c == '\\' && i+1 < n:
			b = append(b, pattern[i+1]) // the escaped byte, literally
			i += 2
		case c == '^' || c == '$':
			i++ // anchor: contributes no literal
		case c == '[':
			// Character class: emit a representative letter for a simple
			// case/letter set (`[cC]` -> 'C'); skip a complex one (ranges /
			// negation).  Scan to the matching ']'.
			j := i + 1
			for j < n && pattern[j] != ']' {
				j++
			}
			if j >= n { // unterminated '[': treat as a plain stop
				i = n
				break
			}
			if rep := classRep(pattern[i+1 : j]); rep != 0 {
				b = append(b, rep)
			}
			i = j + 1
		case c == '(':
			// Group.  Once a real literal is in hand the group is a trailing
			// qualifier (`AdsBot-Google([^-]|$)`) -> stop.  A leading group is
			// usually an anchor/alternation wrapper (`(^| )PTST`) -> emit its
			// first literal alternative, if any, and continue past it.
			end := groupEnd(pattern, i)
			if len(strings.Trim(string(b), "/.-_ ")) >= 2 {
				i = n
				break
			}
			if lit := firstAltLiteral(pattern[i+1 : end]); lit != "" {
				b = append(b, lit...)
			}
			i = end + 1
		case c == '|' || c == '*' || c == '+' || c == '?' || c == '{':
			i = n // remaining constructs: stop here
		default:
			b = append(b, c)
			i++
		}
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

// classRep returns a representative byte for a character-class body, or 0 when
// the class carries no clean letter (a range `a-z` or negation `^...`).  It
// prefers an uppercase ASCII letter (so `[cC]` -> 'C', matching the usual
// capitalisation of the crawler name) and otherwise takes the first letter.
func classRep(inner string) byte {
	if strings.IndexByte(inner, '-') >= 0 || strings.IndexByte(inner, '^') >= 0 {
		return 0
	}
	var first byte
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c >= 'A' && c <= 'Z' {
			return c
		}
		if first == 0 && c >= 'a' && c <= 'z' {
			first = c
		}
	}
	return first
}

// groupEnd returns the index of the ')' closing the '(' at start, accounting
// for nesting; if unterminated it returns the last index.
func groupEnd(s string, start int) int {
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return len(s) - 1
}

// firstAltLiteral splits a group body on top-level '|' and returns the first
// alternative's leading literal run (letters / digits / -._/), or "" when no
// alternative starts with one (e.g. `^| ` -> "").
func firstAltLiteral(body string) string {
	for _, alt := range splitTopAlt(body) {
		var b []byte
		for i := 0; i < len(alt); i++ {
			c := alt[i]
			if c == '\\' && i+1 < len(alt) {
				i++
				b = append(b, alt[i])
				continue
			}
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
				c == '-' || c == '.' || c == '_' || c == '/' {
				b = append(b, c)
				continue
			}
			break
		}
		if s := strings.Trim(string(b), "/.-_ "); s != "" {
			return s
		}
	}
	return ""
}

// splitTopAlt splits on '|' that are not nested inside parentheses or a
// character class.
func splitTopAlt(body string) []string {
	var out []string
	depth, start := 0, 0
	inClass := false
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++ // skip the escaped byte
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '(':
			if !inClass {
				depth++
			}
		case ')':
			if !inClass && depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 && !inClass {
				out = append(out, body[start:i])
				start = i + 1
			}
		}
	}
	return append(out, body[start:])
}
