// Package classify: classify a bot kind from UA + JA4 verdict.
//
// IsBot return values:
//
//	0  Human
//	1  SearchAI         search/AI/ads        (Googlebot / GPTBot / ClaudeBot ... legitimate bots that should pass)
//	2  JA4Bot           ja4_bot              (TLS fingerprint exposes spoofing)
//	4  OldUA            old_ua               (Chrome/Firefox below 30 = classic spoofing signal)
//	5  Service          service              (SEO / monitoring / scanner / archiver / feed-reader)
//	6  UserDev          user_dev             (curl / requests / playwright / puppeteer etc.)
//
// Priority:
//
//	SearchAI > JA4Bot > OldUA > UserDev > Service > Human
//
// Heuristic "per-IP behavior" judgments (= many requests from one IP etc.) are out of scope here.
package classify

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/assets"
)

type Category int

const (
	Human    Category = 0
	SearchAI Category = 1
	JA4Bot   Category = 2
	OldUA    Category = 4
	Service  Category = 5
	UserDev  Category = 6
)

func (c Category) String() string {
	switch c {
	case Human:
		return "human"
	case SearchAI:
		return "search_ai"
	case JA4Bot:
		return "ja4_bot"
	case OldUA:
		return "old_ua"
	case Service:
		return "service"
	case UserDev:
		return "user_dev"
	}
	return "unknown"
}

// JSON tag → internal category
var tagCategory = map[string]string{
	"search-engine":      "search_ai",
	"ai-crawler":         "search_ai",
	"advertising":        "search_ai",
	"seo":                "service",
	"monitoring":         "service",
	"social-preview":     "service",
	"scanner":            "service",
	"feed-reader":        "service",
	"archiver":           "service",
	"academic":           "service",
	"http-library":       "user_dev",
	"browser-automation": "user_dev",
}

// Generic patterns not included in the JSON.
var extraUserDev = []string{
	"curl", "wget", "python-requests", "axios", "libwww-perl",
	"go-http-client", "java/", "okhttp", "node-fetch", "httpx", "httpclient",
	"scrapy",
	"headlesschrome", "playwright", "puppeteer", "phantomjs", "selenium", "cypress",
}
var extraService = []string{
	"nikto", "nmap", "masscan", "zgrab", "nuclei", "sqlmap",
	"xymon", "nagios", "zabbix", "prometheus",
	`bot\b`, "crawler", "spider", "slurp",
	"monitoring",
	// The original Perl was `fetch(?!\.)` (= "fetch" not followed by ".").
	// RE2 lacks negative lookahead, so rewrite as an equivalent: "fetch
	// followed by something other than '.' or end of line".
	`fetch(?:[^.]|$)`,
}

// Legitimate browser UA prefix.
var knownBrowserRE = regexp.MustCompile(
	`^Mozilla/5\.0\s.*\s(?:Chrome|Safari|Firefox|Edge?)/[0-9]` +
		`|^Mozilla/5\.0\s.*\sOPR/[0-9]` +
		`|^Opera/[0-9]`,
)

// Old-browser detection.
var oldBrowserRE = regexp.MustCompile(
	`Chrome/(\d+)\b|Firefox/(\d+)\b|rv:(\d+)\.\d`,
)

type categoryREs struct {
	searchAI *regexp.Regexp
	service  *regexp.Regexp
	userDev  *regexp.Regexp
}

var (
	cache     *categoryREs
	cacheOnce sync.Once
)

func getCategoryREs() *categoryREs {
	cacheOnce.Do(func() {
		raw := assets.CrawlerUserAgentsJSON
		// The UNMASK_CRAWLER_UA_JSON env var overrides the binary-embedded
		// data.  This lets `unmask-admin update-crawler-list` apply the
		// latest JSON without a rebuild.
		if path := os.Getenv("UNMASK_CRAWLER_UA_JSON"); path != "" {
			if b, err := os.ReadFile(path); err == nil && len(b) > 1024 {
				raw = b
			} else if err != nil {
				log.Printf("classify: failed to read %s, falling back to embedded: %v", path, err)
			}
		}
		cache = buildCategoryREs(raw)
	})
	return cache
}

// buildCategoryREs is exported via getCategoryREs but factored for tests.
func buildCategoryREs(jsonRaw []byte) *categoryREs {
	var data []struct {
		Pattern string   `json:"pattern"`
		Tags    []string `json:"tags"`
	}
	var searchAI, service, userDev []string

	if len(jsonRaw) > 0 {
		// Replace invalid bytes with '?' (= drop entries that contain invalid utf-8).
		clean := sanitizeUTF8(jsonRaw)
		if err := json.Unmarshal(clean, &data); err != nil {
			log.Printf("classify: crawler-user-agents.json decode failed: %v", err)
		}
	}

	for _, ent := range data {
		if ent.Pattern == "" {
			continue
		}
		// priority: search_ai > service > user_dev
		var cat string
	outer:
		for _, prio := range [...]string{"search_ai", "service", "user_dev"} {
			for _, t := range ent.Tags {
				if tagCategory[t] == prio {
					cat = prio
					break outer
				}
			}
		}
		if cat == "" {
			cat = "service"
		}
		switch cat {
		case "search_ai":
			searchAI = append(searchAI, ent.Pattern)
		case "user_dev":
			userDev = append(userDev, ent.Pattern)
		default:
			service = append(service, ent.Pattern)
		}
	}

	userDev = append(userDev, extraUserDev...)
	service = append(service, extraService...)

	return &categoryREs{
		searchAI: joinAlt(searchAI),
		service:  joinAlt(service),
		userDev:  joinAlt(userDev),
	}
}

// joinAlt builds a case-insensitive `(?i)(?:p1|p2|...)`.
//
// Upstream JSON (= crawler-user-agents) and extra patterns may contain
// Perl-only syntax (lookahead, backreferences, etc.), so validate each
// pattern individually with `regexp.Compile` and only keep the ones that
// compile.  If everything fails / the list is empty, return a regex
// guaranteed to never match.
func joinAlt(parts []string) *regexp.Regexp {
	const never = `\bX\x00DOES_NOT_MATCH_X\x00\b` // guaranteed to match nothing in RE2
	good := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		// Probe whether this pattern compiles standalone, case-insensitive.
		if _, err := regexp.Compile(`(?i)(?:` + p + `)`); err != nil {
			log.Printf("classify: skip unsupported pattern %q: %v", p, err)
			continue
		}
		good = append(good, p)
	}
	if len(good) == 0 {
		return regexp.MustCompile(never)
	}
	return regexp.MustCompile(`(?i)(?:` + strings.Join(good, "|") + `)`)
}

// sanitizeUTF8 replaces non-ASCII bytes with '?' to dodge non-utf8 patterns
// (= occasionally present in upstream JSON).  Does not affect \u escapes inside JSON strings.
func sanitizeUTF8(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x80 {
			out[i] = '?'
		} else {
			out[i] = c
		}
	}
	return out
}

// IsKnownBrowser returns true iff the UA looks like a stock browser
// (Chrome / Safari / Firefox / Edge / Opera).
func IsKnownBrowser(ua string) bool {
	if ua == "" {
		return false
	}
	return knownBrowserRE.MatchString(ua)
}

// IsOldBrowser returns true iff UA claims a pre-30 Chrome/Firefox/Gecko version.
func IsOldBrowser(ua string) bool {
	if ua == "" {
		return false
	}
	for _, m := range oldBrowserRE.FindAllStringSubmatch(ua, -1) {
		var ver string
		for _, g := range m[1:] {
			if g != "" {
				ver = g
				break
			}
		}
		if ver == "" {
			continue
		}
		if v, err := strconv.Atoi(ver); err == nil && v < 30 {
			return true
		}
	}
	return false
}

// IsBot classifies (ua, ja4Action) into one of the Category values.
// ja4Action is one of "bot" / "suspect" / "ok" / "" (= the action enum
// resolved by settings-side matchJA4.  Verdict-name prefix detection has
// been removed).
func IsBot(ua, ja4Action string) Category {
	res := getCategoryREs()
	if ua != "" && res.searchAI.MatchString(ua) {
		return SearchAI
	}
	if ja4Action == "bot" || ja4Action == "suspect" {
		return JA4Bot
	}
	if IsOldBrowser(ua) {
		return OldUA
	}
	if ua != "" && res.userDev.MatchString(ua) {
		return UserDev
	}
	if ua != "" && res.service.MatchString(ua) {
		return Service
	}
	return Human
}
