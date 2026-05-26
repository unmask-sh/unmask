// Package nginxconf: embed data + render functions for the nginx config
// fragments used by unmask-admin's `render-nginx` sub-command.
//
// Philosophy:
//   - The only file a user edits is /etc/unmask/config.yml.
//   - Search-bot UAs / JA4 verdicts are kept as presets at group
//     granularity, so groups can be toggled on/off and extra patterns
//     can be added.
//   - The presets are updated with each admin release.
package nginxconf

// init: when AddedIn is empty on a preset group, default it to "v0.1".
//
// New presets that explicitly set AddedIn: "v0.5" etc. get a
// "since v0.5" label in the UI.  Existing groups keep their initial
// release.
func init() {
	for i := range SearchBotGroups {
		if SearchBotGroups[i].AddedIn == "" {
			SearchBotGroups[i].AddedIn = "v0.1"
		}
	}
	for i := range ChallengeTargetGroups {
		if ChallengeTargetGroups[i].AddedIn == "" {
			ChallengeTargetGroups[i].AddedIn = "v0.1"
		}
	}
	for i := range JA4VerdictGroups {
		if JA4VerdictGroups[i].AddedIn == "" {
			JA4VerdictGroups[i].AddedIn = "v0.1"
		}
	}
	for i := range HoneypotPresetGroups {
		if HoneypotPresetGroups[i].AddedIn == "" {
			HoneypotPresetGroups[i].AddedIn = "v0.1"
		}
	}
	for i := range BypassPathPresetGroups {
		if BypassPathPresetGroups[i].AddedIn == "" {
			BypassPathPresetGroups[i].AddedIn = "v0.1"
		}
	}
	for i := range ProtectedPathPresetGroups {
		if ProtectedPathPresetGroups[i].AddedIn == "" {
			ProtectedPathPresetGroups[i].AddedIn = "v0.1"
		}
	}
}

// SearchBotGroup: preset group for search / AI / ad-bot UAs.
//
// Carries an ID + Label so groups can be disabled.  Writing the ID
// into config.yml's nginx.search_bots.disabled_presets turns it off.
//
// AddedIn tracks when each preset was introduced (= the admin
// release that added it).  Initial release is "v0.1".  When bumping
// the release, new groups get the latest version (= the UI labels
// them "since vX").
// ID design for SearchBotGroup:
//
//	The group-level string ID (= "google" / "bing" etc.) is the
//	rename-safe identifier.  disabled_presets in config.yml refers
//	to this ID.  Rules (= each pattern) are just a UA regex array
//	without per-rule attributes (= action / verdict), so unlike
//	JA4VerdictRule there is no numeric-ID linkage to DB columns.  If
//	you only need to rename a pattern, swap the string in the
//	array.  ChallengeTargetGroup / HoneypotGroup follow the same
//	design.
type SearchBotGroup struct {
	ID       string
	Label    string
	Patterns []string
	AddedIn  string
	// DefaultOnWhenNew: bypass the IsNew force-uncheck behavior. Use for
	// reorganizations that should preserve "allowed by default" for bots
	// that were previously allowed via a different preset (= avoid silent
	// regression where a NEW preset would otherwise block them). The NEW
	// badge is still shown in the UI for user awareness.
	DefaultOnWhenNew bool
}

// SearchBotGroups: search-bot UA presets.  Updated per release.
//
// Sending a search bot through the challenge gets it stuck because JS
// won't run, which leads to index removal and a ranking drop.  The
// UAs listed here are let through the challenge.
//
// Patterns are evaluated with nginx's case-insensitive substring
// match (= "~*").
var SearchBotGroups = []SearchBotGroup{
	{
		ID:    "google",
		Label: "Google (Googlebot / AdsBot / Mediapartners / InspectionTool)",
		Patterns: []string{
			"Googlebot",
			"Google-InspectionTool",
			"Mediapartners-Google",
			"AdsBot-Google",
		},
	},
	{
		ID:    "bing",
		Label: "Bing / Microsoft (bingbot / msnbot / BingPreview)",
		Patterns: []string{
			"bingbot",
			"msnbot",
			"BingPreview",
		},
	},
	{
		ID:       "yahoo",
		Label:    "Yahoo (Slurp)",
		Patterns: []string{"Slurp"},
	},
	{
		ID:       "naver",
		Label:    "Naver (Yeti)",
		Patterns: []string{"Yeti/"},
	},
	{
		ID:    "yandex",
		Label: "Yandex",
		Patterns: []string{
			"YandexBot",
			"YandexImages",
			"YandexAccessibilityBot",
		},
	},
	{
		ID:       "baidu",
		Label:    "Baidu (Baiduspider)",
		Patterns: []string{"Baiduspider"},
	},
	{
		ID:       "sogou",
		Label:    "Sogou",
		Patterns: []string{"Sogou web spider"},
	},
	{
		ID:       "duckduckgo",
		Label:    "DuckDuckGo",
		Patterns: []string{"DuckDuckBot"},
	},
	{
		ID:       "apple",
		Label:    "Apple (Applebot)",
		Patterns: []string{"Applebot"},
	},
	// AI vendor presets (openai / anthropic / perplexity) were removed
	// in v0.2 — AI bots now live under the purpose-based ai_training /
	// ai_user presets defined at the end of this list. Orphan entries
	// in existing user DisabledPresets (= "openai" etc.) are silently
	// ignored by render.go (= the loop never finds the ID).
	{
		ID:       "internet_archive",
		Label:    "Internet Archive (ia_archiver)",
		Patterns: []string{"ia_archiver"},
	},
	{
		ID:       "huawei",
		Label:    "Huawei (PetalBot)",
		Patterns: []string{"PetalBot"},
	},
	{
		ID:       "coccoc",
		Label:    "Coc Coc (Vietnam)",
		Patterns: []string{"coccocbot"},
	},
	{
		ID:       "seznam",
		Label:    "Seznam (Czech)",
		Patterns: []string{"SeznamBot"},
	},
	{
		ID:       "qwant",
		Label:    "Qwant (France)",
		Patterns: []string{"Qwantify"},
	},
	// Cross-cutting AI purpose presets (= added v0.2, replacing the
	// removed openai / anthropic / perplexity vendor presets above).
	// Users toggle by purpose ("don't train me, but keep showing me in
	// AI search results"). DefaultOnWhenNew is set so upgrading users
	// don't see AI bots silently blocked.
	{
		ID:               "ai_training",
		Label:            "AI training crawlers (= cross-vendor)",
		AddedIn:          "v0.2",
		DefaultOnWhenNew: true,
		Patterns: []string{
			"GPTBot",
			"ClaudeBot",
			"Claude-Web",
			"Google-Extended",
			"Applebot-Extended",
			"CCBot",
			"Bytespider",
			"meta-externalagent",
			"cohere-ai",
			"anthropic-ai",
			"Diffbot",
			"omgili",
		},
	},
	{
		ID:               "ai_user",
		Label:            "AI user/search crawlers (= live retrieval for user queries)",
		AddedIn:          "v0.2",
		DefaultOnWhenNew: true,
		Patterns: []string{
			"ChatGPT-User",
			"OAI-SearchBot",
			"Claude-User",
			"Claude-SearchBot",
			"PerplexityBot",
			"Perplexity-User",
			"PerplexityUser",
			"MistralAI-User",
			"YouBot",
		},
	},
}

// JA4VerdictGroup: preset group mapping a JA4 fingerprint pattern ->
// verdict label + action.
//
// verdict and action play different roles:
//   - verdict is a free-form label for humans / dashboard / log (= no naming convention enforced).
//   - action is an enum that decides nginx's behavior (= "bot" | "suspect" | "ok").
//
// Meaning of action values:
//   - "bot"     : real bot verdict.  Challenge HTML skips PoW and goes straight to CAPTCHA.
//   - "suspect" : likely spoofed but not confirmed.  Normal challenge flow.  Observe in the log.
//   - "ok"      : not subject to the challenge (= equivalent to having the preset OFF).
//
// Caution: never treat Googlebot's JA4 as a bot.  It's not in any of
// these presets, but be careful not to add it via user extras.
type JA4VerdictGroup struct {
	ID      string
	Label   string
	Rules   []JA4VerdictRule
	AddedIn string
}

type JA4VerdictRule struct {
	// ID: rename-safe immutable identifier.  Built-in IDs 1-99 are
	// hard-coded.  Extras (= added by the user via the settings UI)
	// are auto-numbered 100+ (= AssignExtraID in preset.go).  Stored
	// in the unmask_event.ja4_verdict_id column.  Dashboard display
	// is ID -> current Verdict lookup.  0 is reserved for
	// "unknown / not in preset".
	ID      int
	Pattern string // nginx regex (= specify without the leading ~^)
	Verdict string // free-form label.  For log / dashboard display (= rename freely).
	Action  string // "bot" | "suspect" | "ok".  Determines nginx behavior.
}

// Valid action values.  Templates / handlers validate against these.
const (
	JA4ActionBot     = "bot"
	JA4ActionSuspect = "suspect"
	JA4ActionOK      = "ok"
)

// IsValidJA4Action: validate the action value.
func IsValidJA4Action(a string) bool {
	return a == JA4ActionBot || a == JA4ActionSuspect || a == JA4ActionOK
}

// IsBotAction: is the action a bot-class one (= challenge / includes
// suspect)?  Shared decision used by dashboard aggregation and
// classify to identify "verdicts treated as bot."
func IsBotAction(a string) bool {
	return a == JA4ActionBot || a == JA4ActionSuspect
}

// ID numbering rules: built-ins use rule-by-rule sequential numbers
// from 1-99.  Numbers are **never reused** on rule add/remove
// (= deleted IDs stay as gaps).  Renaming keeps the ID and only
// updates Verdict, so the DB doesn't need a migration.  Extras start
// at 100+.
var JA4VerdictGroups = []JA4VerdictGroup{
	{
		ID:    "chrome_fake",
		Label: "Chrome-style cipher spoofing (= 8daaf6152771 + non-h2 ALPN)",
		Rules: []JA4VerdictRule{
			{ID: 1, Pattern: "t13d[0-9]+h1_8daaf6152771_", Verdict: "chrome_fake_h1", Action: JA4ActionBot},
			{ID: 2, Pattern: "t13d[0-9]+00_8daaf6152771_", Verdict: "chrome_fake_noalpn", Action: JA4ActionBot},
		},
	},
	{
		ID:    "rotating_proxy",
		Label: "Residential proxy that rotates many UAs",
		Rules: []JA4VerdictRule{
			{ID: 3, Pattern: "t13d1812h1_85036bcba153_", Verdict: "h1_18_12", Action: JA4ActionBot},
			{ID: 4, Pattern: "t13d4412h1_fd39b124ee10_", Verdict: "h1_44_12", Action: JA4ActionBot},
			{ID: 5, Pattern: "t13d311[01]00_e8f1e7e78f70_", Verdict: "noalpn_311", Action: JA4ActionBot},
			{ID: 6, Pattern: "t13d521100_b262b3658495_", Verdict: "noalpn_521", Action: JA4ActionBot},
		},
	},
	{
		ID:    "tls12",
		Label: "Using TLS 1.2 + a known signature (= modern browsers are TLS 1.3)",
		Rules: []JA4VerdictRule{
			{ID: 7, Pattern: "t12d660600_d16616bd43e4_", Verdict: "tls12_a", Action: JA4ActionBot},
			{ID: 8, Pattern: "t12d430700_1ce71f0edbb1_", Verdict: "tls12_b", Action: JA4ActionBot},
			{ID: 9, Pattern: "t12d210700_76e208dd3e22_", Verdict: "tls12_c", Action: JA4ActionBot},
		},
	},
	{
		ID:    "h1_lax",
		Label: "Lenient: Chrome-style cipher + any ALPN h1 (= suspect)",
		Rules: []JA4VerdictRule{
			{ID: 10, Pattern: "t13d[0-9]+h1_", Verdict: "h1_lax", Action: JA4ActionSuspect},
		},
	},
}

// ChallengeTargetGroup: presets for UA categories that should receive
// the challenge HTML when a bot signal trips.
//
// Philosophy:
//   - The 動作モード tab covers the "known browser / unknown UA" split for
//     the no-match path, so a `known_browser` preset here is gone — it
//     would double-dip with the Global axis and confuse the resolution
//     order.
//   - cli / python_libs / node_libs / go_libs / java_libs / headless were
//     also removed in favour of the upstream rescue groups (= http-library
//   - browser-automation, default black).  Same UA coverage, single
//     source of truth.
//   - What remains here are presets that don't fit any upstream category
//     (= empty / very short UA) and are still worth flagging.
type ChallengeTargetGroup struct {
	ID       string
	Label    string
	Patterns []string // nginx case-insensitive regex (= evaluated with ~*)
	AddedIn  string   // admin version added (= e.g. "v0.1".  UI labels "since vX")
}

var ChallengeTargetGroups = []ChallengeTargetGroup{
	{
		ID:    "empty",
		Label: "Empty UA / extremely short UA (= 5 chars or fewer)",
		Patterns: []string{
			// Express "5 chars or fewer" as `^.{0,5}$`.  No normal browser string fits.
			`^.{0,5}$`,
		},
	},
}

// HoneypotGroup: preset group for honeypot paths.  Same shape as
// search bots etc.
//
// Disable per group.  Putting the ID into
// config.yml's nginx.honeypot.disabled_presets turns it OFF.
//
// Essence of the honeypot feature: "Trip it -> we record IP+JA4 in
// the persistent BAN list.  What happens next depends on the user's
// nginx.conf ($unmask_banned variable)."  There is no mode concept,
// so the row UI is simple (= 4 columns: path + title + enabled +
// updated_at).  CAPTCHA / PoW / strict choices are managed in the
// "protected paths" tab.
type HoneypotGroup struct {
	ID       string
	Label    string
	Patterns []string
	AddedIn  string
	// OptIn: when true, the group ships disabled and only renders when the
	// operator explicitly names it in settings.Honeypot.EnabledPresets.
	// Reserved for patterns whose false-positive surface area is wider than
	// pure scanner paths (= sql-injection, where a site search can echo SQL
	// keywords by accident).  Default false matches the historical opt-out
	// shape that the on-by-default presets already use.
	OptIn bool
}

var HoneypotPresetGroups = []HoneypotGroup{
	{
		ID:    "wordpress",
		Label: "WordPress (wp-login / wp-admin / xmlrpc / themes)",
		Patterns: []string{
			`/wp-login\.php`,
			`/wp-admin`,
			`/xmlrpc\.php`,
			`/wp-content/themes/.*\.php`,
		},
	},
	{
		ID:    "secrets",
		Label: "Secret-leak scan (.env / .git / aws / config.json)",
		Patterns: []string{
			`/\.env(?:$|/|\?)`,
			`/\.git/config`,
			`/\.aws/credentials`,
			`/config\.json`,
			`/secrets\.json`,
		},
	},
	{
		ID:    "cms-admin",
		Label: "CMS / admin-panel probing (phpmyadmin / adminer / admin.php)",
		Patterns: []string{
			`/phpmyadmin`,
			`/myadmin`,
			`/adminer\.php`,
			`/admin\.php`,
			`/manage(?:r|ment)?/html`,
		},
	},
	{
		ID:    "shell",
		Label: "shell upload (c99 / r57 / .php~ etc.)",
		Patterns: []string{
			`\.php~$`,
			`/shell\.php`,
			`/c99\.php`,
			`/r57\.php`,
		},
	},
	{
		ID:    "cgi-tomcat",
		Label: "CGI / Tomcat (cgi-bin / manager/text)",
		Patterns: []string{
			`/cgi-bin/(?!debug-static$)`,
			`/manager/text`,
		},
	},
	{
		ID:    "scan-paths",
		Label: "Typical scanner paths (server-status / actuator)",
		Patterns: []string{
			`/server-status`,
			`/actuator/(env|heapdump|trace)`,
		},
	},
	// SQL injection signatures: high-confidence query-string patterns that
	// almost never appear in legitimate browser traffic.  Trip = persistent
	// BAN like any other honeypot.  Default OFF -- site-search endpoints can
	// legitimately echo SQL keywords ("?q=order by date") and the operator
	// should grep their access_log for the patterns below first.  Patterns
	// are evaluated against $request_uri so they cover both the path and the
	// query string in one shot; the case-insensitive `~*` flag on the
	// rendered map absorbs UNION / Union / union variations.
	{
		ID:    "sql-injection",
		Label: "SQL injection signatures (sqlmap / probes; OFF by default -- audit site search before enabling)",
		OptIn: true,
		Patterns: []string{
			// Classic boolean-based: ' OR '1'='1 / ' OR 1=1
			`'\s*or\s+'?1'?\s*=\s*'?1`,
			// UNION SELECT (= URLs almost never need this verbatim)
			`union\s+select`,
			// sqlmap reconnaissance
			`information_schema\.(tables|columns)`,
			`concat\(0x[0-9a-f]+`,
			// MSSQL timing / RCE
			`waitfor\s+delay`,
			`xp_cmdshell`,
			// MySQL timing / file access
			`sleep\(\s*\d+\s*\)`,
			`benchmark\(\s*\d+\s*,`,
			`into\s+outfile`,
			`load_file\(`,
			// Destructive
			`;\s*drop\s+(table|database)`,
		},
		AddedIn: "v0.1.0",
	},
}
