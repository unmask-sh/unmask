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
	for _, tag := range res.tagOrder {
		if re := res.tagRE[tag]; re != nil && re.MatchString(ua) {
			return tag
		}
	}
	return ""
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
	for _, tag := range out.tagOrder {
		out.tagRE[tag] = joinAlt(perTag[tag])
	}
	return out
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
var chromeMajorRE = regexp.MustCompile(`Chrome/(\d+)\.`)

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
var firefoxMajorRE = regexp.MustCompile(`Firefox/(\d+)\.`)

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
	uaEdgeRE       = regexp.MustCompile(`Edg(?:e|A|iOS)?/(\d+)`)
	uaOperaRE      = regexp.MustCompile(`OPR/(\d+)`)
	uaSamsungRE    = regexp.MustCompile(`SamsungBrowser/(\d+)`)
	uaCriOSRE      = regexp.MustCompile(`CriOS/(\d+)`)
	uaFxiOSRE      = regexp.MustCompile(`FxiOS/(\d+)`)
	uaSafariVerRE  = regexp.MustCompile(`Version/(\d+)(?:\.\d+)?.*Safari/`)
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
func UASummary(ua string) string {
	if ua == "" {
		return ""
	}
	platform := uaPlatform(ua)
	browser, ver := uaBrowser(ua)
	if platform == "" || browser == "" {
		return ""
	}
	if ver != "" {
		browser += " " + ver
	}
	return platform + " · " + browser
}

// uaPlatform: device first, then desktop OS.  Order matters -- an Android
// tablet UA also says "Linux", and every iOS UA says "like Mac OS X".
func uaPlatform(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"):
		return "iPhone"
	case strings.Contains(ua, "iPad"):
		return "iPad"
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
		if !strings.Contains(ua, "Mobile") && !strings.Contains(ua, "; wv") {
			label += " Tab"
		}
		return label
	case strings.Contains(ua, "CrOS"):
		return "ChromeOS"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		return "Mac"
	case strings.Contains(ua, "Windows"):
		// Deliberately no version: every current Windows reports "NT 10.0",
		// so printing it would suggest a precision the UA does not carry.
		return "Windows"
	case strings.Contains(ua, "Ubuntu"):
		return "Ubuntu"
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		return "Linux"
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
	if v := first(uaSamsungRE); v != "" {
		return "Samsung", v
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
	// Safari last: it is the token every WebKit UA carries, so reaching here
	// means none of the more specific ones matched.
	if v := first(uaSafariVerRE); v != "" {
		return "Safari", v
	}
	return "", ""
}
