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
	"slices"
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

// JSON tag → internal category.  Tags that DefaultGroupMode treats as
// `black` (= scanner / http-library / browser-automation) deliberately do
// NOT map into "search_ai" — otherwise IsBot would short-circuit to
// SearchAI ("pass") for curl / Selenium / nmap, while the nginx render
// puts the same UAs into $is_challenge_target.  Keeping them in
// `service` lets AuthCheck fall through to lookupUAListed where the
// per-axis ResolveGroupMode decides "challenge" symmetrically with nginx.
var tagCategory = map[string]string{
	"search-engine":  "search_ai",
	"ai-crawler":     "search_ai",
	"ai-training":    "search_ai",
	"ai-user":        "search_ai",
	"advertising":    "search_ai",
	"seo":            "search_ai",
	"monitoring":     "search_ai",
	"social-preview": "search_ai",
	"feed-reader":    "search_ai",
	"archiver":       "search_ai",
	"academic":       "search_ai",
	// Below default to GroupModeBlack via DefaultGroupMode.  Keep them out of
	// search_ai so the challenge path can reach them via lookupUAListed.
	"scanner":            "service",
	"http-library":       "service",
	"browser-automation": "service",
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

	tagCache     *crawlerTagREs
	tagCacheOnce sync.Once
)

// crawlerTagREs: per-tag regex set built from crawler-user-agents.json.
// Lets callers ask "which crawler tag does this UA match" beyond the rough
// SearchAI / Service / UserDev split — used by the dashboard's AI-traffic
// breakdown card so we can distinguish ai-crawler / ai-training / ai-user
// / search-engine etc. instead of collapsing them all to search_ai.
type crawlerTagREs struct {
	tagOrder []string                  // lookup priority (= AI tags first)
	tagRE    map[string]*regexp.Regexp // tag → compiled regex
	// litGate / ungatedRE: a cheap pre-filter for LookupTag.  Matching the
	// joined per-tag alternations costs ~1ms for a UA that is not a crawler at
	// all -- nearly every row the hunt log renders -- so a UA is first checked
	// against the literal each pattern must contain.
	//
	// A handful of patterns start with a character class or group and offer no
	// mandatory literal ("[wW]get", "(sistrix|SISTRIX) [cC]rawler", ...).
	// Those are compiled into ungatedRE and always matched, so the filter
	// never turns "unknown" into "not a crawler".
	litGate   []string
	ungatedRE *regexp.Regexp
}

// CrawlerTagOrder is the public lookup priority — AI-flavoured tags come
// first so a UA that matches both an AI tag and a generic one resolves to
// the more specific AI tag.
var CrawlerTagOrder = []string{
	"ai-training",
	"ai-user",
	"ai-crawler",
	"search-engine",
	"advertising",
	"seo",
	"monitoring",
	"social-preview",
	"notification-preview",
	"feed-reader",
	"archiver",
	"academic",
}

// NotificationPreviewTag marks preview fetchers that run on subscribers' OWN
// devices (Apple's notification service extensions fetching a push
// notification's rich preview).  Unlike the social-preview unfurlers, whose
// requests come from vendor servers, these arrive from residential IPs with
// no publishable ranges -- so the UA string is the entire spoof surface, and
// the tag's rescue is guarded: it fires only together with the Apple TLS
// fingerprint below (both deploy modes).  Because of that, the tag's entries
// deliberately join NONE of the IsBot category buckets: search_ai would
// rescue on UA alone in forward-auth, and the unmapped-tag "service" default
// would challenge-target the UA there while native stayed neutral.
const NotificationPreviewTag = "notification-preview"

// AppleCFNetworkJA4B is the JA4_b segment (cipher-suite hash) of Apple's
// CFNetwork / Network.framework TLS stack, as observed stable across
// CFNetwork builds on Darwin 24 and 25 over both HTTP/1.1 and HTTP/2.
// JA4_a and JA4_c drift with OS releases (extension counts / order), but the
// cipher list has held; matching only the _b segment keeps the guard from
// rotting on every Apple update while still costing a spoofer TLS-stack
// mimicry instead of one header line.  Underscores anchor the segment.
const AppleCFNetworkJA4B = "_a09f3c656075_"

// MatchesTag reports whether ua matches one of tag's crawler-list patterns.
func MatchesTag(ua, tag string) bool {
	if ua == "" {
		return false
	}
	re := getCrawlerTagREs().tagRE[tag]
	return re != nil && re.MatchString(ua)
}

// LookupTag returns the first crawler-user-agents.json tag matched by ua,
// or "" when none matches.  Tag lookup priority is CrawlerTagOrder.
// Safe for concurrent use.
func LookupTag(ua string) string {
	if ua == "" {
		return ""
	}
	res := getCrawlerTagREs()
	if !crawlerGatePasses(res, ua) {
		return ""
	}
	for _, tag := range res.tagOrder {
		if re := res.tagRE[tag]; re != nil && re.MatchString(ua) {
			return tag
		}
	}
	return ""
}

// crawlerGatePasses reports whether ua can possibly be a crawler, cheaply.
// False means no pattern can match; true means the per-tag regexes have to
// run to find out which.
func crawlerGatePasses(res *crawlerTagREs, ua string) bool {
	low := strings.ToLower(ua)
	for _, lit := range res.litGate {
		if strings.Contains(low, lit) {
			return true
		}
	}
	return res.ungatedRE != nil && res.ungatedRE.MatchString(ua)
}

func getCrawlerTagREs() *crawlerTagREs {
	tagCacheOnce.Do(func() {
		raw := assets.CrawlerUserAgentsJSON
		if path := os.Getenv("UNMASK_CRAWLER_UA_JSON"); path != "" {
			if b, err := os.ReadFile(path); err == nil && len(b) > 1024 {
				raw = b
			}
		}
		tagCache = buildCrawlerTagREs(raw)
	})
	return tagCache
}

// buildCrawlerTagREs groups every JSON entry by its tag list — an entry
// with multiple tags contributes its pattern to each one — and compiles a
// joinAlt regex per tag.  Tags absent from the JSON simply get a never-
// matching regex.
func buildCrawlerTagREs(jsonRaw []byte) *crawlerTagREs {
	var data []struct {
		Pattern string   `json:"pattern"`
		Tags    []string `json:"tags"`
	}
	if len(jsonRaw) > 0 {
		clean := sanitizeUTF8(jsonRaw)
		if err := json.Unmarshal(clean, &data); err != nil {
			log.Printf("classify: crawler-user-agents.json decode failed (tag build): %v", err)
		}
	}
	perTag := map[string][]string{}
	for _, ent := range data {
		if ent.Pattern == "" {
			continue
		}
		for _, t := range ent.Tags {
			perTag[t] = append(perTag[t], ent.Pattern)
		}
	}
	out := &crawlerTagREs{
		tagOrder: append([]string{}, CrawlerTagOrder...),
		tagRE:    map[string]*regexp.Regexp{},
	}
	seen := map[string]bool{}
	ungated := []string{}
	for _, tag := range out.tagOrder {
		out.tagRE[tag] = joinAlt(perTag[tag])
		for _, pat := range perTag[tag] {
			lit := longestLiteralRun(pat)
			if lit == "" {
				ungated = append(ungated, pat)
				continue
			}
			if !seen[lit] {
				seen[lit] = true
				out.litGate = append(out.litGate, lit)
			}
		}
	}
	if len(ungated) > 0 {
		out.ungatedRE = joinAlt(ungated)
	}
	return out
}

// longestLiteralRun extracts a literal run that any matching UA must contain:
// the FIRST run of literal characters, taken before the pattern's first
// alternation.  Every UA that matches the pattern contains it, which is the
// property the pre-filter needs.
//
// Taking the longest run instead would be unsound: in "Ahrefs(Bot|SiteAudit)"
// the longest run is "SiteAudit", which "AhrefsBot/6.1" does not contain --
// the gate would drop a real crawler.  The verification test caught exactly
// that.  Runs shorter than 2 characters are rejected as too weak to filter on.
func longestLiteralRun(pattern string) string {
	best, cur := "", strings.Builder{}
	stop := false
	flush := func() {
		if stop {
			return
		}
		if cur.Len() > len(best) {
			best = cur.String()
		}
		cur.Reset()
	}
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\\' && i+1 < len(pattern):
			// An escaped literal ends the run: the escaped char may be a
			// separator we do not want to fold into the token.
			i++
			flush()
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '!' || c == '-' || c == '_' || c == ' ':
			// Letters, digits, and the punctuation that appears literally in
			// these patterns.  "Y!J" and "um-LN" are whole crawler names whose
			// only literal run needs the "!" / "-" to reach usable length.
			cur.WriteByte(c)
		default:
			// Any operator or punctuation: the run stops here.  A quantifier
			// could make the preceding character optional, so drop the last
			// byte before accepting the run.
			if (c == '?' || c == '*') && cur.Len() > 0 {
				t := cur.String()
				cur.Reset()
				cur.WriteString(t[:len(t)-1])
			}
			flush()
			// Past an alternation or group, later runs are only required on
			// SOME branch -- stop collecting so the result stays mandatory.
			if c == '(' || c == '|' || c == '[' {
				stop = true
			}
		}
	}
	flush()
	// Two characters is the floor: four upstream patterns ("Y!J", "um-LN",
	// "PR-CY\.RU", "^BW\/") have no longer literal run, and rejecting them
	// would switch the gate off for the whole list.  A 2-char token filters
	// less, but it filters soundly, which is the property that matters.
	if len(best) < 2 {
		return ""
	}
	return strings.ToLower(best)
}

func getCategoryREs() *categoryREs {
	cacheOnce.Do(func() {
		raw := assets.CrawlerUserAgentsJSON
		// The UNMASK_CRAWLER_UA_JSON env var overrides the binary-embedded
		// data.  This lets `unmask update-crawler-list` apply the
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
		// Guarded tags stay out of every category bucket: their rescue is
		// UA + TLS fingerprint (see NotificationPreviewTag), so search_ai
		// would over-rescue and the "service" fallback below would
		// challenge-target the UA asymmetrically with native.
		if slices.Contains(ent.Tags, NotificationPreviewTag) {
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

// chromeMajorRE captures the Chromium-family major version.  Every
// Chromium-based browser — Chrome, Edge, Opera, Brave, Vivaldi, Samsung
// Internet, and headless Chromium — carries a `Chrome/<major>` token and
// shares Google's ~4-week major-release cadence, so one number covers the
// whole family.  Firefox and Safari (WebKit) use unrelated version schemes
// and carry no Chrome token, so ChromeMajor returns 0 for them (= never
// treated as a stale Chrome).
// No trailing dot: a genuine build reports Chrome/131.0.0.0, but simplified
// and forged UAs state a bare major ("Chrome/131") -- and this column shows
// the claim as reported, so the bare form must parse too.  (HeadlessChrome
// matches either way; the dot never excluded it.)
var chromeMajorRE = regexp.MustCompile(`Chrome/(\d+)`)

// SecCHUAMinChromeMajor is the first Chromium major that sends Sec-CH-UA
// (user-agent client hints shipped in Chromium 89, 2021-03).  Below it the
// header's absence is normal, so the header-integrity axis must stay silent --
// see headerDecide.  The nginx-rendered $unmask_ua_chromium map encodes the
// same floor as a regex; keep the two in step.
const SecCHUAMinChromeMajor = 89

// ChromeMajor returns the Chromium-family major version a UA advertises, or 0
// when the UA carries no `Chrome/<major>.` token (genuine Firefox / Safari /
// most bots / empty).  The trailing dot anchors the major so `Chrome/139` is
// read from `Chrome/139.0.7258.5` without mis-reading a build number.
func ChromeMajor(ua string) int {
	if ua == "" {
		return 0
	}
	m := chromeMajorRE.FindStringSubmatch(ua)
	if m == nil {
		return 0
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return v
}

// firefoxMajorRE captures the Firefox major version.  Desktop and Android
// Firefox carry a `Firefox/<major>.` token and follow the same ~4-week major
// cadence as Chromium, so one lag knob covers both families.  iOS Firefox
// (FxiOS/) is WebKit with its own version scheme and carries no Firefox
// token — FirefoxMajor returns 0 for it, like for Safari itself.
// Same reasoning as chromeMajorRE: accept a bare "Firefox/128".
var firefoxMajorRE = regexp.MustCompile(`Firefox/(\d+)`)

// FirefoxMajor returns the Firefox major version a UA advertises, or 0 when
// the UA carries no `Firefox/<major>.` token.  The trailing dot anchors the
// major the same way ChromeMajor's does.
func FirefoxMajor(ua string) int {
	if ua == "" {
		return 0
	}
	m := firefoxMajorRE.FindStringSubmatch(ua)
	if m == nil {
		return 0
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return v
}

// IsStaleBrowser reports whether a UA advertises a Chromium-family or Firefox
// major that is at least lagN releases behind that family's current stable
// (operator-maintained / shipped baselines, since unmask cannot know them on
// its own).  A distributed scraper that pins one outdated build (the
// 2026-07-15 uic.io incident pinned Chrome/139 while stable was 150) is
// caught here; a genuine visitor on a slightly old browser is at most a few
// majors behind and is not.
//
// Chromium and Firefox share the ~4-week major cadence, so one lagN spans
// both families.  ffESRExempt lists the supported Firefox ESR majors (both
// the old and the new one during a transition window): ESR is a fully
// patched release that legitimately trails stable by up to ~15 majors
// (enterprise / Debian default), so without the exemption every ESR user
// would be challenged.  A bot pinning exactly an ESR UA slips this tier —
// the cost of not CAPTCHAing the real ESR population; the other axes
// (JA4 / rate-limit / behavioral) still apply to it.
//
// Safari is NOT covered by design: its major numbering jumped (18 → 26 in
// 2025), breaking "N behind" arithmetic, and its version is pinned to the OS
// — old-but-genuine Safari UAs are far more common than old Chrome ones.  A
// Safari UA carries neither token and passes untouched.
//
// Returns false when the feature inputs are unset (both currents <=0 or
// both lags <=0) or the UA carries neither token, so callers can pass raw
// config without pre-guarding.  The comparison is "at least lag behind"
// (current-major >= lag): with current=150 and lag=11, Chrome/139 and older
// are stale while Chrome/140+ pass.  The lag is per family -- the release
// cadences match today, but one major stops meaning the same amount of time
// if they diverge, so each family compares against its own N.
func IsStaleBrowser(ua string, curChrome, curFirefox int, ffESRExempt []int, lagChrome, lagFirefox int) bool {
	if curChrome > 0 && lagChrome > 0 {
		if major := ChromeMajor(ua); major > 0 {
			return curChrome-major >= lagChrome
		}
	}
	if curFirefox > 0 && lagFirefox > 0 {
		if major := FirefoxMajor(ua); major > 0 {
			for _, esr := range ffESRExempt {
				if esr > 0 && major == esr {
					return false
				}
			}
			return curFirefox-major >= lagFirefox
		}
	}
	return false
}

// UpstreamRescueEntry is one UA pattern auto-rescued via crawler-user-agents.json
// (= tagged search-engine / ai-crawler / advertising → SearchAI → pass).
// Exposed for the settings UI ua-filter tab so the maintainer can see exactly
// which patterns are pass-listed (the operator's extra UA rules).
type UpstreamRescueEntry struct {
	Pattern      string   `json:"pattern"`
	Tags         []string `json:"tags"`
	URL          string   `json:"url,omitempty"`
	Description  string   `json:"description,omitempty"`
	Category     string   `json:"category"`                // primary rescue tag (= search-engine / ai-crawler / advertising)
	AdditionDate string   `json:"addition_date,omitempty"` // upstream "YYYY/MM/DD" string, optional
}

// UpstreamRescueList returns the entries that get auto-rescued via the upstream
// crawler-user-agents.json.  Grouped by primary rescue category for UI display.
// Loads the same data source as classify (= embedded JSON, or the file pointed
// to by UNMASK_CRAWLER_UA_JSON if set).
func UpstreamRescueList() map[string][]UpstreamRescueEntry {
	raw := assets.CrawlerUserAgentsJSON
	if path := os.Getenv("UNMASK_CRAWLER_UA_JSON"); path != "" {
		if b, err := os.ReadFile(path); err == nil && len(b) > 1024 {
			raw = b
		}
	}
	return parseUpstreamRescue(raw)
}

func parseUpstreamRescue(jsonRaw []byte) map[string][]UpstreamRescueEntry {
	out := map[string][]UpstreamRescueEntry{}
	if len(jsonRaw) == 0 {
		return out
	}
	var data []struct {
		Pattern      string   `json:"pattern"`
		Tags         []string `json:"tags"`
		URL          string   `json:"url"`
		Description  string   `json:"description"`
		AdditionDate string   `json:"addition_date"`
	}
	clean := sanitizeUTF8(jsonRaw)
	if err := json.Unmarshal(clean, &data); err != nil {
		log.Printf("classify: UpstreamRescueList decode failed: %v", err)
		return out
	}
	for _, ent := range data {
		if ent.Pattern == "" {
			continue
		}
		// Explicit priority: the upstream JSON sometimes carries the finer
		// ai-user / ai-training tags directly; honour those before the
		// generic ai-crawler / search-engine / etc.  Any entry tagged with
		// none of these is skipped (= not part of the auto-pass surface).
		var primary string
		for _, p := range []string{"ai-user", "ai-training", "search-engine", "advertising", "seo", "social-preview", NotificationPreviewTag, "feed-reader", "archiver", "academic", "monitoring", "scanner", "http-library", "browser-automation", "ai-crawler"} {
			for _, t := range ent.Tags {
				if t == p {
					primary = p
					break
				}
			}
			if primary != "" {
				break
			}
		}
		if primary == "" {
			continue
		}
		// ai-crawler is a fallback bucket — entries tagged only "ai-crawler"
		// without the finer ai-training / ai-user subdivision get split by a
		// pattern-name heuristic.
		if primary == "ai-crawler" {
			primary = aiSubcategory(ent.Pattern)
		}
		out[primary] = append(out[primary], UpstreamRescueEntry{
			Pattern:      ent.Pattern,
			Tags:         ent.Tags,
			URL:          ent.URL,
			Description:  ent.Description,
			Category:     primary,
			AdditionDate: ent.AdditionDate,
		})
	}
	return out
}

// aiUserHintRE flags patterns that represent a user-initiated fetch through
// an AI tool's UI (ChatGPT / Claude / Perplexity / Mistral / DuckAssist /
// Gemini deep-research), as opposed to a background training crawler.  The
// upstream JSON tags both kinds as "ai-crawler", so the distinction is
// derived heuristically from the pattern name.
var aiUserHintRE = regexp.MustCompile(`(?i)(?:[-_]user\b|[-_]web\b|\bchatgpt[-_]|\bclaude[-_]web\b|\bdeep[-_]research\b|\bassist(?:bot)?\b)`)

// aiSubcategory splits an "ai-crawler" pattern into "ai-user" (= user-driven
// fetch from an AI assistant UI) or "ai-training" (= autonomous crawler that
// gathers training data).
func aiSubcategory(pattern string) string {
	if aiUserHintRE.MatchString(pattern) {
		return "ai-user"
	}
	return "ai-training"
}

// upstreamDisabledRE holds the compiled regex of UA patterns that should
// NOT be auto-rescued via the upstream list, even if they match the
// search_ai category.  Set via SetUpstreamDisabled by the settings handler
// whenever settings change.  nil means "no patterns disabled" (= default
// behavior: all upstream matches pass).
var (
	upstreamDisabledMu sync.RWMutex
	upstreamDisabledRE *regexp.Regexp
)

// GroupModeWhite / Black / None: roles a upstream-rescue group can play.
//
//	white -> the group's patterns are auto-passed (= "is_search_bot=1").
//	black -> the group's patterns are challenge-targets (= "is_challenge_target=1").
//	none  -> the group is inert (= patterns get no special handling).
const (
	GroupModeWhite = "white"
	GroupModeBlack = "black"
	GroupModeNone  = "none"
)

// DefaultGroupMode returns the built-in default role for an upstream
// category.  Benign categories default to white (auto-pass).  Categories
// that typically attack or scrape default to black (challenge-target).
func DefaultGroupMode(cat string) string {
	switch cat {
	case "scanner", "http-library", "browser-automation":
		return GroupModeBlack
	}
	// search-engine / ai-training / ai-user / advertising / seo / monitoring
	// / social-preview / feed-reader / archiver / academic (and the
	// ai-crawler fallback) all default to white.
	return GroupModeWhite
}

// ResolveGroupMode returns the effective mode for cat: the override entry
// if present, otherwise DefaultGroupMode(cat).  An override value outside
// {white, black, none} is treated as "no override" and falls back to the
// default.
func ResolveGroupMode(cat string, overrides map[string]string) string {
	if overrides != nil {
		if v, ok := overrides[cat]; ok {
			switch v {
			case GroupModeWhite, GroupModeBlack, GroupModeNone:
				return v
			}
		}
	}
	return DefaultGroupMode(cat)
}

// PresetGroupSpec is a minimal {ID, Patterns} pair used by callers that
// want to feed ChallengeTargetGroups (or any similarly shaped preset list)
// into ResolvePresetActionForUA without dragging the nginxconf package into
// classify (= avoids an import cycle).
type PresetGroupSpec struct {
	ID       string
	Patterns []string
}

// ResolvePresetActionForUA matches the UA against the given preset list and
// returns the per-preset action override if any.  Presets whose ID appears
// in disabled are skipped (= matches the nginx render's "disabled preset"
// semantics).  Empty string = no override applies.
func ResolvePresetActionForUA(ua string, groups []PresetGroupSpec, overrides map[string]string, disabled map[string]bool) string {
	if ua == "" || len(overrides) == 0 {
		return ""
	}
	for _, g := range groups {
		if disabled != nil && disabled[g.ID] {
			continue
		}
		act, ok := overrides[g.ID]
		if !ok || act == "" {
			continue
		}
		re := joinAlt(g.Patterns)
		if re != nil && re.MatchString(ua) {
			return act
		}
	}
	return ""
}

// ResolveActionForUA matches the UA string against the upstream rescue
// groups currently resolved to "black" mode and returns the per-group
// action override if any.  Empty string = no per-group override (caller
// should fall back to the global default).
//
// modeOverrides + actionOverrides come from settings.SearchBots.
func ResolveActionForUA(ua string, modeOverrides, actionOverrides map[string]string) string {
	if ua == "" || len(actionOverrides) == 0 {
		return ""
	}
	groups := UpstreamRescueList()
	for cat, entries := range groups {
		if ResolveGroupMode(cat, modeOverrides) != GroupModeBlack {
			continue
		}
		act, ok := actionOverrides[cat]
		if !ok || act == "" {
			continue
		}
		pats := make([]string, 0, len(entries))
		for _, e := range entries {
			pats = append(pats, e.Pattern)
		}
		re := joinAlt(pats)
		if re != nil && re.MatchString(ua) {
			return act
		}
	}
	return ""
}

// SetUpstreamDisabled rebuilds the per-pattern disable filter from the
// settings UI.  Patterns listed here are removed from the search_ai pass
// path: they will fall through to ja4 / old-ua / user_dev / service /
// human classification instead.
func SetUpstreamDisabled(patterns []string) {
	upstreamDisabledMu.Lock()
	defer upstreamDisabledMu.Unlock()
	if len(patterns) == 0 {
		upstreamDisabledRE = nil
		return
	}
	upstreamDisabledRE = joinAlt(patterns)
}

// IsBot classifies (ua, ja4Action) into one of the Category values.
// ja4Action is one of "bot" / "suspect" / "ok" / "" (= the action enum
// resolved by settings-side matchJA4.  Verdict-name prefix detection has
// been removed).
func IsBot(ua, ja4Action string) Category {
	res := getCategoryREs()
	if ua != "" && res.searchAI.MatchString(ua) {
		// Honor the per-pattern disable list (= settings UI). A search_ai
		// hit that matches a disabled pattern falls through to the other
		// classification branches instead of pass.
		upstreamDisabledMu.RLock()
		disabled := upstreamDisabledRE
		upstreamDisabledMu.RUnlock()
		if disabled == nil || !disabled.MatchString(ua) {
			return SearchAI
		}
		// fallthrough
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

// (AICategory has been retired in favour of LookupTag, which preserves all
// 11 upstream tags instead of collapsing them to 5 buckets.  The crawler-
// minute aggregation now stores tags directly.)

// ---------------------------------------------------------------------------
// UA summary for the events table
// ---------------------------------------------------------------------------

var (
	uaAndroidVerRE = regexp.MustCompile(`Android (\d+)`)
	uaIPhoneVerRE  = regexp.MustCompile(`iPhone OS (\d+)_(\d+)`)
	uaIPadVerRE    = regexp.MustCompile(`CPU OS (\d+)_(\d+)`)
	uaWinNTVerRE   = regexp.MustCompile(`Windows NT ([\d.]+)`)
	uaCrOSVerRE    = regexp.MustCompile(`CrOS \S+ (\d+)`)
	uaEdgeRE       = regexp.MustCompile(`Edg(?:e|A|iOS)?/(\d+)`)
	uaOperaRE      = regexp.MustCompile(`OPR/(\d+)`)
	// Pre-Chromium Opera: "Opera/9.80 ... Version/12.16" (the real release is
	// in Version/, Opera/ is frozen at 9.x) and the Presto engine token.
	// 745 hits on live traffic, none of which resolved to a browser before --
	// and a 2013-era Opera in 2026 is itself worth seeing.
	uaOperaOldRE  = regexp.MustCompile(`Opera[/ ](\d+)`)
	uaOperaVerRE  = regexp.MustCompile(`Opera.*Version/(\d+)`)
	uaOperaMiniRE = regexp.MustCompile(`Opera Mini`)
	uaSamsungRE   = regexp.MustCompile(`SamsungBrowser/(\d+)`)
	uaCriOSRE     = regexp.MustCompile(`CriOS/(\d+)`)
	uaFxiOSRE     = regexp.MustCompile(`FxiOS/(\d+)`)
	uaSafariVerRE = regexp.MustCompile(`Version/(\d+)(?:\.\d+)?.*Safari/`)
	// In-app browsers.  These are ordinary humans arriving through an app's
	// embedded WebView, and several carry no Safari/Chrome token at all -- so
	// they fell through every branch above and the row lost its summary
	// entirely, showing the raw UA where every other human row showed
	// "platform · browser".  Named apps rather than a generic "WebView"
	// because which app sent the traffic is the useful part.
	uaDalvikRE   = regexp.MustCompile(`Dalvik/(\d+)`)
	uaOkHTTPRE   = regexp.MustCompile(`okhttp/(\d+)`)
	uaLineRE     = regexp.MustCompile(`Line/(\d+)`)
	uaYJAppRE    = regexp.MustCompile(`YJApp-(?:IOS|ANDROID)`)
	uaGSARE      = regexp.MustCompile(`GSA/(\d+)`)
	uaFacebookRE = regexp.MustCompile(`FBA[VN]`)
	uaInstaRE    = regexp.MustCompile(`Instagram (\d+)`)
	uaWeChatRE   = regexp.MustCompile(`MicroMessenger/(\d+)`)
	uaKakaoRE    = regexp.MustCompile(`KAKAOTALK`)
	uaSmartNewRE = regexp.MustCompile(`SmartNews/(\d+)`)
	// Trident is IE's engine.  A "Trident/3.1" does not exist (real ones are
	// 4.0-7.0), so this token shows up mainly on forged UAs -- naming it beats
	// leaving the row unsummarised, and the version is worth showing because
	// an impossible one is itself the signal.
	uaTridentRE = regexp.MustCompile(`Trident/(\d+\.\d+)`)
	uaMSIERE    = regexp.MustCompile(`MSIE (\d+)`)
	// Both separators appear in the wild: "10_15_7" (Safari / Chrome) and
	// "10.13" (Firefox).  Matching only "_" truncated the Firefox form to its
	// major number -- "Mac OS X 10.13" was reported as "Mac 10".
	uaMacVerRE = regexp.MustCompile(`Mac OS X (\d+(?:[._]\d+)*)`)
	// A desktop-Linux UA carries no OS version at all -- "X11" is a bare
	// token with no number behind it, and there is no kernel or distro
	// release in the string.  The architecture is the one real fact it does
	// carry, and it earns its place: 32-bit (i686) desktops effectively do
	// not exist any more, so seeing one is itself a signal.
	uaWin9xRE     = regexp.MustCompile(`Windows (95|98|ME|CE|XP|2000|Me)\b`)
	uaLinuxArchRE = regexp.MustCompile(`Linux (x86_64|i[3-6]86|aarch64|armv\d+l|ppc64le|riscv64)`)
	// uaSelfBotRE: a UA naming itself a bot.  crawler-user-agents.json is a
	// curated list and cannot keep up with every crawler that shows up -- live
	// traffic is led by Amzn-SearchBot and AzureAI-SearchBot, neither of which
	// is on it -- but these clients all self-identify with a token ending in
	// bot / crawler / spider / scanner / checker.  Taking them at their word
	// costs nothing: the name is what the operator needs, and a client lying
	// ABOUT being a bot is not a threat model.
	// Anchored on the keyword and scanned outward by botTokenAt rather than
	// matched with a lazy alternation: the regex form took 3ms per UA, which
	// a 1000-row hunt page pays in full.
	uaBotWords = []string{"bot", "crawler", "spider", "scanner", "checker", "inspect"}
)

// UASummary condenses a browser user agent into "<platform> · <browser> <major>"
// for the events table, where the raw string is 700+px wide and every human
// visitor's begins with the same "Mozilla/5.0 (...) AppleWebKit/537.36 (KHTML,
// like Gecko)" boilerplate -- so the column shows a lot and distinguishes
// nothing.  The full value stays one click away (the cell carries it as
// data-full-value for the popover).
//
// Returns "" when the UA is not a recognisable browser, and the caller then
// shows the raw string.  That fallback is deliberate: the events table is a
// bot-hunting surface, and a UA that does NOT summarise -- curl, a library, a
// crawler, something malformed -- is one whose exact bytes the operator is
// most likely to want in front of them.  Summarising those into "Other" (as a
// dashboard for human traffic reasonably would) throws away the evidence.
//
// The version is kept, unlike a plain "Windows Edge" label: unmask's own
// decisions turn on it (the stale-browser tier compares majors, the
// header-integrity axis has a hard boundary at Chromium 89), so a row whose
// version is invisible cannot be checked against the reason it was escalated.
// uaSummaryCache memoises UASummary.  The function is pure, and the hunt log
// renders up to 1000 rows in one page where the same UA repeats constantly (a
// bot hammering with one string is the normal case).  Without this, the
// crawler lookup below -- a walk over the joined per-tag regexes built from
// crawler-user-agents.json -- ran per row and cost 1.7s for a full page.
//
// Bounded and cleared wholesale when it fills: the key is attacker-controlled,
// so it must not grow without limit, and an LRU's bookkeeping would cost more
// than the occasional rebuild it saves.
var (
	uaSummaryMu    sync.Mutex
	uaSummaryMemo  = map[string]string{}
	uaSummaryLimit = 4096
)

func UASummary(ua string) string {
	if ua == "" {
		return ""
	}
	uaSummaryMu.Lock()
	if v, ok := uaSummaryMemo[ua]; ok {
		uaSummaryMu.Unlock()
		return v
	}
	uaSummaryMu.Unlock()
	v := uaSummaryUncached(ua)
	uaSummaryMu.Lock()
	if len(uaSummaryMemo) >= uaSummaryLimit {
		uaSummaryMemo = make(map[string]string, uaSummaryLimit)
	}
	uaSummaryMemo[ua] = v
	uaSummaryMu.Unlock()
	return v
}

func uaSummaryUncached(ua string) string {
	// A known crawler's NAME is the whole story -- "Googlebot" says more than
	// any platform/browser reading of the same string, and several crawlers
	// (Googlebot, Bingbot) ship a full Chrome-shaped UA that would otherwise
	// summarise as an ordinary desktop browser and hide what they are.  This
	// is also what makes a spoof visible: an unverified request claiming
	// Googlebot lands in the hunt log wearing the name it claimed.
	//
	// The curated list runs BEFORE the self-declared scan.  It used to be the
	// other way around for cost (the scan settles in ~2us, the list walk in
	// ~3ms) on the assumption that a listed bot's declared name equals its
	// list name -- which Google-Extended broke: its UA carries no bot-shaped
	// product token at all, only "+http://www.google.com/bot.html", so the
	// scan extracted a literal "bot" out of the URL while the list knew the
	// real name.  The memo above absorbs the walk once per UA kind, so the
	// cost argument no longer buys anything.  uaBotKind resolves the badge
	// KIND through the same list-first order, so name and colour stay from
	// one source.
	if c, _ := LookupCrawler(ua); c != "" && c != "other" {
		return c
	}
	if b := SelfDeclaredBot(ua); b != "" {
		return b
	}
	platform := uaPlatform(ua)
	browser, ver := uaBrowser(ua)
	if platform == "" {
		// No platform, but the client still named itself ("okhttp/5.3.0"):
		// show that rather than falling back to the raw string, which for
		// these is the same text with more noise around it.
		if browser != "" {
			if ver != "" {
				return browser + " " + ver
			}
			return browser
		}
		return ""
	}
	if browser == "" {
		// The UA names a platform but carries no browser token: a truncated
		// or hand-built string ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)
		// AppleWebKit/537.36"), which is itself worth seeing.  Showing the
		// platform alone beats falling back to the raw string -- the row stays
		// the same shape as its neighbours, and the missing half is the
		// signal.  The full string is one click away in the popover.
		return platform
	}
	if ver != "" {
		browser += " " + ver
	}
	return platform + " · " + browser
}

// SelfDeclaredBot returns the bot name a UA gives for itself, or "" when it
// does not name one.  Used for clients that are not on the curated crawler
// list; see uaSelfBotRE.
func SelfDeclaredBot(ua string) string {
	// Cheap gate before the regex.  The pattern is lazy and alternating, so
	// running it on every UA cost ~4.5ms on a string that has no bot token at
	// all -- and every ordinary browser UA is such a string.  A UA that names
	// itself must contain one of these words, so a plain substring scan
	// decides it first.
	low := strings.ToLower(ua)
	if !strings.Contains(low, "bot") && !strings.Contains(low, "crawler") &&
		!strings.Contains(low, "spider") && !strings.Contains(low, "scanner") &&
		!strings.Contains(low, "checker") && !strings.Contains(low, "inspect") {
		return ""
	}
	// Find the earliest keyword, then walk backwards over the name characters
	// that precede it -- "compatible; Amzn-SearchBot/0.1)" yields
	// "Amzn-SearchBot".  A plain scan, so the cost is the length of the UA.
	best := -1
	bestEnd := 0
	for _, w := range uaBotWords {
		if i := strings.Index(low, w); i >= 0 && (best < 0 || i < best) {
			best, bestEnd = i, i+len(w)
		}
	}
	if best < 0 {
		return ""
	}
	start := best
	for start > 0 {
		c := ua[start-1]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' {
			start--
			continue
		}
		break
	}
	// Trailing name characters after the keyword ("Googlebot2" style).
	end := bestEnd
	for end < len(ua) {
		c := ua[end]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			end++
			continue
		}
		break
	}
	name := strings.Trim(ua[start:end], "-._")
	if len(name) < 3 {
		return ""
	}
	return name
}

// UAPlatformIcon returns an emoji for the platform a UA summary starts with,
// or "" when there is nothing recognisable to draw.
//
// It reads the SUMMARY rather than the raw UA so the icon can never disagree
// with the text beside it -- one classification, two renderings.  The icon is
// added to the label, never substituted for it: an emoji alone would not be
// searchable, copyable or readable to a screen reader, and several of these
// platforms have no glyph anyone recognises.
func UAPlatformIcon(summary string) string {
	switch {
	case summary == "":
		return ""
	case strings.HasPrefix(summary, "iPhone"), strings.HasPrefix(summary, "iPad"),
		strings.HasPrefix(summary, "Mac"):
		return "\U0001F34E" // apple
	case strings.HasPrefix(summary, "Windows"):
		return "\U0001FA9F" // window
	case strings.HasPrefix(summary, "Android"):
		return "\U0001F916" // robot
	case strings.HasPrefix(summary, "ChromeOS"):
		return "\U0001F310" // globe
	case strings.HasPrefix(summary, "Ubuntu"), strings.HasPrefix(summary, "Linux"):
		return "\U0001F427" // penguin
	}
	return ""
}

// UABrowserColor returns a brand colour for the browser named at the end of a
// UA summary, or "" when there is none to show.
//
// Deliberately a colour and not an emoji, unlike the platform.  🍎 / 🪟 / 🐧 /
// 🤖 are symbols people already read as Apple / Windows / Linux / Android; no
// such glyph exists for Chrome, Edge or IE, so assigning one would invent a
// legend the operator has to learn -- and any compass-for-Safari style guess
// collides with the next browser that has an equal claim to it.  A brand
// colour needs no lookup to be useful: it makes rows scannable in bulk while
// the name beside it stays the authority.
// UASummaryParts splits a summary into its platform half and browser half so
// the UI can put a marker in front of EACH.  Returns ("", summary) when there
// is no browser half (a crawler name, an app with no platform).
func UASummaryParts(summary string) (platform, browser string) {
	i := strings.LastIndex(summary, " · ")
	if i < 0 {
		return "", summary
	}
	return summary[:i], summary[i+len(" · "):]
}

// uaBrowserName strips a trailing version from a browser half.  Only when the
// tail is actually a number: several app names carry spaces of their own
// ("Yahoo! JAPAN App"), and cutting at the last space would eat the name.
func uaBrowserName(browser string) string {
	// A version tail is digits, optionally dotted ("3.1" is Trident's).  An
	// app name can carry spaces of its own ("Yahoo! JAPAN App"), so only a
	// numeric tail is treated as a version.
	if j := strings.LastIndexByte(browser, ' '); j > 0 && isVersionTail(browser[j+1:]) {
		return browser[:j]
	}
	return browser
}

func isVersionTail(s string) bool {
	if s == "" {
		return false
	}
	digit := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			digit = true
		case s[i] == '.':
		default:
			return false
		}
	}
	return digit
}

// UABrowserIcon returns the id of the sprite symbol drawn for a browser, or ""
// when there is no drawn icon for it.  Only the browsers that actually carry
// the traffic get one -- Chrome, Edge, Firefox and Safari are nearly all of
// it -- because a drawn mark is only worth its space while it is recognised
// on sight; everything else keeps the brand-coloured dot.
func UABrowserIcon(summary string) string {
	_, b := UASummaryParts(summary)
	switch uaBrowserName(b) {
	case "Chrome":
		return "chrome"
	case "Edge":
		return "edge"
	case "Firefox":
		return "firefox"
	case "Safari":
		return "safari"
	case "IE", "Trident":
		// Drawn like the others rather than left to the grey dot: a browser
		// that stopped shipping in 2022 is mostly a forged UA, so the row
		// deserves to be as identifiable at a glance as a real one.
		return "ie"
	case "Opera", "Opera Mini":
		return "opera"
	case "Google App":
		return "gsa"
	case "Yahoo! JAPAN App":
		return "yjapp"
	case "LINE":
		return "line"
	case "In-app browser", "App (Dalvik)":
		// The platform half decides which glyph: an app WebView is a
		// different thing to look at on an iPhone than on a Mac, and Android
		// app traffic (Dalvik) is not a WebView at all.  Live traffic carries
		// all three (iOS 257, macOS 90, Android 159).
		p, _ := UASummaryParts(summary)
		switch {
		case strings.HasPrefix(p, "iPhone"), strings.HasPrefix(p, "iPad"),
			strings.HasPrefix(p, "Mac"):
			return "wv-apple"
		case strings.HasPrefix(p, "Android"):
			return "wv-android"
		}
		return "wv"
	}
	return ""
}

func UABrowserColor(summary string) string {
	_, b := UASummaryParts(summary)
	if b == summary {
		return "" // no browser half at all
	}
	b = uaBrowserName(b)
	switch b {
	case "Chrome":
		return "#4285f4"
	case "Firefox":
		return "#ff7139"
	case "Safari":
		return "#1b9df0"
	case "Edge":
		return "#0f7c9e"
	case "Opera":
		return "#e4353d"
	case "Samsung":
		return "#1428a0"
	case "IE", "Trident":
		// No brand nostalgia: a browser that has not shipped since 2022 is
		// mostly a forged UA, and grey is the right amount of attention.
		return "#94a3b8"
	case "App (Dalvik)":
		return "#3ddc84"
	case "In-app browser":
		return "#94a3b8"
	case "okhttp":
		return "#5d8f3f"
	case "LINE":
		return "#06c755"
	case "Yahoo! JAPAN App":
		return "#ff0033"
	case "Google App":
		return "#4285f4"
	case "SmartNews":
		return "#ea4b3b"
	case "Instagram":
		return "#c13584"
	case "Facebook":
		return "#1877f2"
	case "WeChat":
		return "#07c160"
	case "KakaoTalk":
		return "#fee500"
	}
	return ""
}

// uaPlatform: device first, then desktop OS.  Order matters -- an Android
// tablet UA also says "Linux", and every iOS UA says "like Mac OS X".
func uaPlatform(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"):
		return "iPhone" + uaDottedVer(uaIPhoneVerRE, ua)
	case strings.Contains(ua, "iPad"):
		return "iPad" + uaDottedVer(uaIPadVerRE, ua)
	case strings.Contains(ua, "Android"):
		label := "Android"
		if m := uaAndroidVerRE.FindStringSubmatch(ua); m != nil {
			label += " " + m[1]
		}
		// "Mobile" is what separates a phone from a tablet in Chrome's own
		// Android UA; without it the build is a tablet / TV / car head unit.
		// An in-app WebView ("; wv") is exempt: those routinely omit Mobile
		// on phones, so the tablet label would be wrong for a large slice of
		// ordinary app traffic.
		// Dalvik is exempt for the same reason as an in-app WebView: the
		// runtime UA never carries "Mobile", so every app request from a
		// phone was being labelled a tablet (live traffic shows Pixel 8a /
		// 9a arriving as "Android 17 Tab").
		if !strings.Contains(ua, "Mobile") && !strings.Contains(ua, "; wv") &&
			!strings.Contains(ua, "Dalvik/") {
			label += " Tab"
		}
		return label
	case strings.Contains(ua, "CrOS"):
		if m := uaCrOSVerRE.FindStringSubmatch(ua); m != nil {
			return "ChromeOS " + m[1]
		}
		return "ChromeOS"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		// Safari and Chrome freeze this field at "10_15_7" on every macOS from
		// Catalina onward -- live traffic pairs it with Safari 26, i.e. macOS
		// 26 -- so that ONE value means "10.15 or anything newer".
		//
		// Shown with a "+" rather than dropped.  This column reports what the
		// client said; deciding a value is too unreliable to display is not
		// its job, and the Windows branch already settled the identical
		// question the other way ("Windows NT 10.0" is equally 10-or-11 and
		// renders as "Windows 10+").  The marker is what keeps it honest: the
		// number is the client's, the "+" is ours.
		if m := uaMacVerRE.FindStringSubmatch(ua); m != nil {
			v := strings.ReplaceAll(m[1], "_", ".")
			raw := strings.ReplaceAll(m[1], ".", "_")
			if i := strings.LastIndexByte(v, '.'); i > 0 && strings.Count(v, ".") > 1 {
				v = v[:i] // 12.0.0 -> 12.0
			}
			if raw == "10_15_7" {
				return "Mac 10.15+"
			}
			return "Mac " + v
		}
		return "Mac"
	case strings.Contains(ua, "Windows"):
		if v := uaWindowsVer(ua); v != "" {
			return "Windows" + v
		}
		// Pre-NT names carry the release in the token itself ("Windows 98",
		// "Windows CE").  They are ancient enough that a real one is unlikely,
		// which is exactly why they should be rendered rather than dropped --
		// live traffic carries 174 "Windows 98" hits.
		if m := uaWin9xRE.FindStringSubmatch(ua); m != nil {
			return "Windows " + m[1]
		}
		return "Windows"
	case strings.Contains(ua, "Ubuntu"):
		return "Ubuntu" + uaLinuxArch(ua)
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		return "Linux" + uaLinuxArch(ua)
	}
	return ""
}

// uaLinuxArch renders the architecture a Linux UA carries as " x86_64" etc.,
// or "" when it names none.  This is the only hardware/OS fact a desktop-Linux
// UA actually holds -- there is no kernel or distro version in the string, and
// "X11" carries no number of its own.
func uaLinuxArch(ua string) string {
	if m := uaLinuxArchRE.FindStringSubmatch(ua); m != nil {
		return " " + m[1]
	}
	return ""
}

// uaBrowser: the derived engines first.  Edge, Opera, Samsung Internet and
// Chrome-on-iOS all carry a "Chrome/" or "Safari/" token of their own, so
// testing for Chrome or Safari first would label every one of them wrong.
func uaBrowser(ua string) (name, ver string) {
	first := func(re *regexp.Regexp) string {
		if m := re.FindStringSubmatch(ua); m != nil {
			return m[1]
		}
		return ""
	}
	if v := first(uaEdgeRE); v != "" {
		return "Edge", v
	}
	if v := first(uaOperaRE); v != "" {
		return "Opera", v
	}
	if uaOperaMiniRE.MatchString(ua) {
		return "Opera Mini", ""
	}
	// Presto-era Opera.  Version/ carries the real release when present
	// ("Opera/9.80 ... Version/12.16" is Opera 12); otherwise the Opera/
	// number is all there is.
	if v := first(uaOperaVerRE); v != "" {
		return "Opera", v
	}
	if v := first(uaOperaOldRE); v != "" {
		return "Opera", v
	}
	if v := first(uaSamsungRE); v != "" {
		return "Samsung", v
	}
	// Named in-app browsers, ahead of Chrome and Safari.  An Android WebView
	// carries the host app's token *and* a Chrome one, so checking Chrome first
	// labelled the same app differently per platform -- LINE on iOS read "LINE"
	// while LINE on Android read "Chrome" (jp: 1915 vs 650 requests).  The app
	// is the identifying half; the engine version stays visible in the popover.
	if v := first(uaLineRE); v != "" {
		return "LINE", v
	}
	if v := first(uaGSARE); v != "" {
		return "Google App", v
	}
	if uaYJAppRE.MatchString(ua) {
		return "Yahoo! JAPAN App", ""
	}
	if v := first(uaSmartNewRE); v != "" {
		return "SmartNews", v
	}
	if v := first(uaInstaRE); v != "" {
		return "Instagram", v
	}
	if uaFacebookRE.MatchString(ua) {
		return "Facebook", ""
	}
	if v := first(uaWeChatRE); v != "" {
		return "WeChat", v
	}
	if uaKakaoRE.MatchString(ua) {
		return "KakaoTalk", ""
	}
	if v := first(uaCriOSRE); v != "" {
		return "Chrome", v
	}
	if v := first(uaFxiOSRE); v != "" {
		return "Firefox", v
	}
	if v := FirefoxMajor(ua); v > 0 {
		return "Firefox", strconv.Itoa(v)
	}
	if v := ChromeMajor(ua); v > 0 {
		return "Chrome", strconv.Itoa(v)
	}
	// Safari last among real browsers: it is the token every WebKit UA
	// carries, so reaching here means none of the more specific ones matched.
	if v := first(uaSafariVerRE); v != "" {
		return "Safari", v
	}
	// Not browsers at all: runtimes that make plain HTTP requests.  These carry
	// no Chrome or Safari token, so their position here is not load-bearing.
	if uaDalvikRE.MatchString(ua) {
		// Android's own runtime UA: an app making a plain HTTP request
		// (HttpURLConnection with no UA set), not a browser.  "App" is the
		// honest word -- no page is being rendered.  The Dalvik version is
		// dropped: it is the runtime's, has been 2.1.0 for a decade, and
		// would read as an app version it is not.
		return "App (Dalvik)", ""
	}
	if v := first(uaOkHTTPRE); v != "" {
		return "okhttp", v
	}
	// A bare WebView: AppleWebKit with no Safari/ and no Version/ after it,
	// which is what WKWebView sends when the host app sets no UA of its own.
	// Safari always appends "Version/x Safari/y", so the absence of both is
	// the tell rather than a guess.
	//
	// Reached only after every named browser and app above, so Chrome,
	// Firefox and LINE keep their own answers -- a Mac Firefox UA also lacks
	// "Safari/" and would be caught here otherwise.  Covers iOS (the
	// "Mobile/" shape, 1779 hits) and macOS (90 hits) alike.
	if strings.Contains(ua, "AppleWebKit") && !strings.Contains(ua, "Safari/") &&
		!strings.Contains(ua, "Version/") {
		return "In-app browser", ""
	}
	// Internet Explorer / anything claiming its engine.
	if v := first(uaMSIERE); v != "" {
		return "IE", v
	}
	if v := first(uaTridentRE); v != "" {
		return "Trident", v
	}
	return "", ""
}

// uaDottedVer renders an "18_7"-style OS version captured as two groups into
// " 18.7", or "" when the UA does not carry one.
func uaDottedVer(re *regexp.Regexp, ua string) string {
	m := re.FindStringSubmatch(ua)
	if m == nil {
		return ""
	}
	return " " + m[1] + "." + m[2]
}

// uaWindowsVer maps the NT kernel version to the marketing name.  Windows 11
// reports the same "NT 10.0" as Windows 10 -- Microsoft never bumped it -- so
// that case renders "10+" rather than claiming a release the UA cannot
// distinguish.  An unknown NT version yields no suffix instead of a guess.
func uaWindowsVer(ua string) string {
	m := uaWinNTVerRE.FindStringSubmatch(ua)
	if m == nil {
		return ""
	}
	switch m[1] {
	case "10.0":
		return " 10+"
	case "6.3":
		return " 8.1"
	case "6.2":
		return " 8"
	case "6.1":
		return " 7"
	case "6.0":
		return " Vista"
	case "5.2":
		return " XP x64"
	case "5.1", "5.01":
		return " XP"
	case "5.0":
		return " 2000"
	case "4.0":
		return " NT 4.0"
	}
	// An NT number with no release name -- "Windows NT 11.0" appears in live
	// traffic and no such version exists.  Report it as given: this column
	// says what the client said, and a value that cannot be real is worth
	// seeing, not hiding.
	return " NT " + m[1]
}

// uaRuleTokenRE: what a black-list pattern is allowed to be.  The value is
// used verbatim as a regex inside a quoted nginx map entry, and escaping is
// not an option there -- a backslash is rejected outright as a way out of the
// quotes -- so the token has to be free of regex meaning to begin with.
var uaRuleTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{3,40}$`)

// UARuleToken: the part of a User-Agent worth turning into a black-list
// pattern -- the name the client calls itself, without the version that will
// have moved on by next week and without the "(+https://example.com/bot)"
// comment.
//
// That comment is the reason this exists.  Self-identifying crawlers write it,
// so it is on exactly the strings an operator wants to list, and "(+" is not a
// valid repeat: the raw UA compiles as a regex nowhere, and nginx refuses the
// whole config at the next reload.
//
// Returns "" when the UA names nothing worth pinning -- an ordinary browser
// string, whose only leading token is "Mozilla" and would match every visitor
// on the site.  Callers offer the full string instead.
func UARuleToken(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return ""
	}
	// The leading product token, for clients that name themselves up front:
	// "OmvionLeadLake/1.0 (...)", "python-requests/2.31.0", "curl/8.0".
	if tok := uaLeadingProduct(ua); tok != "" && !strings.EqualFold(tok, "Mozilla") {
		return tok
	}
	// Otherwise the bot-shaped member of the comment, for the crawlers that
	// wear a browser UA: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://...)".
	return uaCommentBot(ua)
}

// uaLeadingProduct: the product name before the first version / space / comment.
func uaLeadingProduct(ua string) string {
	if i := strings.IndexAny(ua, "/ (;"); i > 0 {
		ua = ua[:i]
	}
	if uaRuleTokenRE.MatchString(ua) {
		return ua
	}
	return ""
}

// uaCommentBot: the first bot-shaped name inside the parenthesised comment.
// URLs are skipped -- "+http://www.google.com/bot.html" contains "bot" and is
// not a name.
func uaCommentBot(ua string) string {
	l := strings.IndexByte(ua, '(')
	r := strings.LastIndexByte(ua, ')')
	if l < 0 || r <= l {
		return ""
	}
	for _, seg := range strings.Split(ua[l+1:r], ";") {
		seg = strings.TrimSpace(seg)
		if seg == "" || strings.HasPrefix(seg, "+") || strings.HasPrefix(strings.ToLower(seg), "http") {
			continue
		}
		name := seg
		if i := strings.IndexAny(name, "/ "); i > 0 {
			name = name[:i]
		}
		low := strings.ToLower(name)
		if !strings.Contains(low, "bot") && !strings.Contains(low, "crawler") &&
			!strings.Contains(low, "spider") && !strings.Contains(low, "scanner") {
			continue
		}
		if uaRuleTokenRE.MatchString(name) {
			return name
		}
	}
	return ""
}
