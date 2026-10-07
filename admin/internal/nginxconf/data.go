// Package nginxconf: embed data + render functions for the nginx config
// fragments used by unmask's `render-nginx` sub-command.
//
// Philosophy:
//   - The only file a user edits is /etc/unmask/config.yml.
//   - Search-bot UAs / JA4 verdicts are kept as presets at group
//     granularity, so groups can be toggled on/off and extra patterns
//     can be added.
//   - The presets are updated with each admin release.
package nginxconf

// init: when AddedIn is empty on a preset group, default it to "v0.1.0".
//
// New presets that explicitly set AddedIn: "v0.5.0" etc. get a "since v0.5.0"
// label in the UI.  Existing (v0.1.0-era) groups keep their initial release.
// A release that changes what an existing preset does -- its patterns or
// rules, its default -- sets the preset's UpdatedIn, shown as "updated vX"
// beside "since"; AddedIn stays the release that first shipped it.
//
// ⚠ A preset that a LATER release adds MUST set AddedIn to that release's
// version.  AddedIn feeds nginxconf.EnforcementHeld: the empty->"v0.1.0"
// default here makes a preset look like it always existed, so an operator on
// the "review" upgrade policy would NEVER see it held for review -- it would
// activate silently on `dnf upgrade`, exactly what upgrade-review exists to
// prevent.  This matters most for ENFORCEMENT presets (JA4 verdict / challenge
// target / honeypot); rescue presets are never held regardless.
func init() {
	for i := range ChallengeTargetGroups {
		if ChallengeTargetGroups[i].AddedIn == "" {
			ChallengeTargetGroups[i].AddedIn = "v0.1.0"
		}
	}
	for i := range JA4VerdictGroups {
		if JA4VerdictGroups[i].AddedIn == "" {
			JA4VerdictGroups[i].AddedIn = "v0.1.0"
		}
	}
	for i := range HoneypotPresetGroups {
		if HoneypotPresetGroups[i].AddedIn == "" {
			HoneypotPresetGroups[i].AddedIn = "v0.1.0"
		}
	}
	for i := range BypassPathPresetGroups {
		if BypassPathPresetGroups[i].AddedIn == "" {
			BypassPathPresetGroups[i].AddedIn = "v0.1.0"
		}
	}
	for i := range ProtectedPathPresetGroups {
		if ProtectedPathPresetGroups[i].AddedIn == "" {
			ProtectedPathPresetGroups[i].AddedIn = "v0.1.0"
		}
	}
	for i := range RedirectExemptPresetGroups {
		if RedirectExemptPresetGroups[i].AddedIn == "" {
			RedirectExemptPresetGroups[i].AddedIn = "v0.1.0"
		}
	}
	for i := range LBIPRanges {
		if LBIPRanges[i].AddedIn == "" {
			LBIPRanges[i].AddedIn = "v0.1.0"
		}
	}
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
	// UpdatedIn: the last release that changed the rules, for the UI ("" when
	// none has).  Shown only: the upgrade review holds by AddedIn.
	UpdatedIn string
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
		Label: "Chrome-style cipher spoofing (8daaf6152771 + non-h2 ALPN)",
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
		Label: "Using TLS 1.2 + a known signature (modern browsers are TLS 1.3)",
		Rules: []JA4VerdictRule{
			{ID: 7, Pattern: "t12d660600_d16616bd43e4_", Verdict: "tls12_a", Action: JA4ActionBot},
			{ID: 8, Pattern: "t12d430700_1ce71f0edbb1_", Verdict: "tls12_b", Action: JA4ActionBot},
			{ID: 9, Pattern: "t12d210700_76e208dd3e22_", Verdict: "tls12_c", Action: JA4ActionBot},
		},
	},
	{
		ID:    "h1_lax",
		Label: "Lenient: Chrome-style cipher + any ALPN h1 (suspect)",
		Rules: []JA4VerdictRule{
			{ID: 10, Pattern: "t13d[0-9]+h1_", Verdict: "h1_lax", Action: JA4ActionSuspect},
		},
	},
}

// ChallengeTargetGroup: presets for UA categories that should receive
// the challenge HTML when a bot signal trips.
//
// Philosophy:
//   - The Operating mode tab covers the "known browser / unknown UA" split for
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
	ID        string
	Label     string
	Patterns  []string // nginx case-insensitive regex (= evaluated with ~*)
	AddedIn   string   // admin version added (= e.g. "v0.1.0".  UI labels "since vX.Y.Z")
	UpdatedIn string   // last release that changed the patterns ("updated vX.Y.Z"); shown only
}

var ChallengeTargetGroups = []ChallengeTargetGroup{
	{
		ID:    "empty",
		Label: "Empty UA / extremely short UA (5 chars or fewer)",
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
	// UpdatedIn: the last release that changed the group -- its patterns,
	// its default -- shown as "updated vX" beside "since".  Shown only.
	UpdatedIn string
	// DefaultOnIn: the release that turned an opt-in group on by default.
	// The upgrade review holds the group from that release rather than from
	// AddedIn, except on an install that had turned it on while it was
	// opt-in: that was the operator's go-ahead (HoneypotGroupHeld).
	DefaultOnIn string
	// OptIn: when true, the group ships disabled and only renders when the
	// operator explicitly names it in settings.Honeypot.EnabledPresets.
	// Reserved for patterns whose false-positive surface area is wider than
	// pure scanner paths.  No group uses it now: sql-injection, the one it was
	// made for, went on by default in v0.1.50.  Default false matches the
	// historical opt-out shape that the on-by-default presets already use.
	OptIn bool
}

// Pieces of the sql-injection patterns, each spelt as it may reach
// $request_uri: as is or percent-encoded (see the group below).  sqlSp is one
// space, + or tab-like byte, or an inline comment (/**/, %2f%2a...%2a%2f).
const (
	sqlSp = `(?:\s|\+|%20|%09|%0a|%0b|%0c|%0d|%a0|/\*.*?\*/|%2f%2a.*?%2a%2f)`
	sqlQ  = `(?:'|%27)`
	sqlEq = `(?:=|%3d)`
	sqlLP = `(?:\(|%28)`
	sqlRP = `(?:\)|%29)`
)

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
	// BAN like any other honeypot.  Shipped opt-in since v0.1.0, on by
	// default since v0.1.50: the patterns need SQL syntax, not SQL words, so
	// a search such as "?q=order by date" and the other ordinary URLs in
	// honeypot_sqli_test.go match nothing.  A site whose search echoes SQL
	// itself ("?q=union select") turns the group off in disabled_presets.
	// DefaultOnIn is the version that turned it on, so an install that
	// reviews new enforcement holds it until reviewed.  Patterns
	// are evaluated against $request_uri so they cover both the path and the
	// query string in one shot; the case-insensitive `~*` flag on the
	// rendered map absorbs UNION / Union / union variations.
	//
	// $request_uri is not decoded, so a probe never carries a literal space:
	// it arrives as %20 or +, and a quote or a bracket may arrive as %27 or
	// %28.  The patterns used to spell \s, ' and ( only, and the UNION SELECT,
	// ' OR '1'='1, WAITFOR DELAY and DROP TABLE probes all went through.  The
	// sql* pieces below accept both spellings (\s stays for the Go wires
	// that may see a decoded string); no lookaround, so nginx's PCRE and Go's
	// RE2 read them alike.
	{
		ID:    "sql-injection",
		Label: "SQL injection signatures (sqlmap / probes)",
		Patterns: []string{
			// Classic boolean-based: ' OR '1'='1 / ' OR 1=1
			sqlQ + sqlSp + `*or` + sqlSp + `+` + sqlQ + `?1` + sqlQ + `?` + sqlSp + `*` + sqlEq + sqlSp + `*` + sqlQ + `?1`,
			// UNION [ALL|DISTINCT] SELECT, UNION(SELECT (= URLs almost never need this verbatim)
			`union(?:` + sqlSp + `|` + sqlLP + `)+(?:(?:all|distinct)(?:` + sqlSp + `|` + sqlLP + `)+)?select`,
			// sqlmap reconnaissance
			`information_schema(?:\.|%2e)(?:tables|columns|schemata)`,
			`concat` + sqlSp + `*` + sqlLP + sqlSp + `*0x[0-9a-f]+`,
			// MSSQL timing / RCE
			`waitfor` + sqlSp + `+delay`,
			`xp_cmdshell`,
			// MySQL timing / file access
			`sleep` + sqlSp + `*` + sqlLP + sqlSp + `*\d+` + sqlSp + `*` + sqlRP,
			`benchmark` + sqlSp + `*` + sqlLP + sqlSp + `*\d+` + sqlSp + `*(?:,|%2c)`,
			`into` + sqlSp + `+(?:out|dump)file`,
			`load_file` + sqlSp + `*` + sqlLP,
			// Destructive
			`(?:;|%3b)` + sqlSp + `*drop` + sqlSp + `+(?:table|database)`,
		},
		UpdatedIn:   "v0.1.50",
		DefaultOnIn: "v0.1.50",
	},
}
