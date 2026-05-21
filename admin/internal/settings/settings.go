// Package settings: YAML config loading.
//
// The config file defaults to /etc/unmask/config.yml.
// The UNMASK_CONFIG environment variable overrides the path.
//
// Layout:
//
//	db:
//	  driver: sqlite | mariadb
//	  sqlite_path: /var/lib/unmask/unmask.sqlite
//	  mariadb:
//	    host: 127.0.0.1
//	    port: 3306
//	    user: unmask
//	    password: ...
//	    database: unmask
//	secret:
//	  bv_secret: <random 32+ chars>      # _bv cookie HMAC-SHA1 key
//	  captcha_secret_base: <random>      # math captcha token HMAC-SHA256 base
//	challenge:
//	  cookie_days: 3
//	  captcha_score_threshold: 0.5
//	  debug_rate_limit_per_5min: 20
//	  challenge_html_path: ""            # empty → use the embedded copy
//	server:
//	  bind: 127.0.0.1
//	  port: 9477
//	  base_path: /unmask                 # URL prefix for the admin app
//
// Authentication uses the internal user DB (= unmask_user table). On first
// startup an admin/superadmin user is auto-created and a random password is
// printed to the log exactly once. The CLI can also manage users:
// `unmask-admin user create / reset-password / set-role / delete`.
package settings

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

var defaultPaths = []string{
	"/etc/unmask/config.yml",
	"/etc/unmask/config.yaml",
}

type DB struct {
	Driver     string  `yaml:"driver"`
	SQLitePath string  `yaml:"sqlite_path"`
	MariaDB    MariaDB `yaml:"mariadb"`
}

type MariaDB struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

type Secret struct {
	BVSecret          string `yaml:"bv_secret"`
	CaptchaSecretBase string `yaml:"captcha_secret_base"`
}

type Challenge struct {
	// CookieSeconds: legacy single-knob _bv lifetime.  Now serves as the
	// fall-back default for {Pow,Captcha}CookieValidSeconds when those are
	// unset.  Browser-side cookie Max-Age is no longer driven by this value
	// (= cookies are written with a fixed 365-day Max-Age so that a server-
	// side window change takes effect immediately on the next request).
	CookieSeconds         int `yaml:"cookie_seconds"`
	// PowCookieValidSeconds: server-side validity window for _bv issued via
	// the PoW path (= 4-segment "pow2" cookie).  0 = inherit CookieSeconds.
	// Granularity is 1 day (= ceil(seconds/86400) used by the nginx HMAC
	// check), so 86400-multiples are practical values.
	PowCookieValidSeconds int `yaml:"pow_cookie_valid_seconds,omitempty"`
	// CaptchaCookieValidSeconds: same but for _bv issued via the CAPTCHA path
	// (= 3-segment HMAC cookie).  0 = inherit CookieSeconds.
	CaptchaCookieValidSeconds int `yaml:"captcha_cookie_valid_seconds,omitempty"`
	// CookieDays: legacy / backward compat. If yaml lacks cookie_seconds but
	// has cookie_days, load-time migrates with CookieSeconds = CookieDays * 86400.
	// Save always writes cookie_seconds only (= cookie_days is not emitted).
	CookieDays              int     `yaml:"cookie_days,omitempty"`
	CaptchaScoreThreshold   float64 `yaml:"captcha_score_threshold"`
	DebugRateLimitPer5Min   int     `yaml:"debug_rate_limit_per_5min"`
	ChallengeHTMLPath       string  `yaml:"challenge_html_path"`
	// PublicTestPages: /unmask/test/ + /unmask/test/{reset-cookie,force-pow,force-captcha}
	// **publicly**. Default false (= 404). /unmask/admin/test/ is always
	// available to logged-in users regardless of this flag. Turning public
	// access ON exposes cookie-clear / PoW / CAPTCHA test pages to anyone,
	// so it should be enabled only for demos or CI smoke tests.
	PublicTestPages bool `yaml:"public_test_pages,omitempty"`
	// CAPTCHA provider: "builtin" (= unmask's standard behavioral) | "turnstile" |
	// "hcaptcha" | "recaptcha" (= reCAPTCHA v3). Default is "builtin".
	CaptchaProvider Captcha `yaml:"captcha,omitempty"`
	// Challenge-page theme. "default" | "cat" etc. Must match the handler-side
	// allowlist (= challengeThemes). Invalid / empty values fall back to "default".
	Theme string `yaml:"theme,omitempty"`
	// PowDifficulty: target leading-zero-bits for the SHA-256 PoW.
	// Practical range is 8-24. Default 18 (= ~262144 iter; modern devices ~500ms,
	// mobile ~1s). Higher = harsher to bots. At 20+ mobile waits seconds.
	PowDifficulty int `yaml:"pow_difficulty,omitempty"`
	// ShowCredit: whether to show the "protected by unmask" credit at the
	// bottom-right of the challenge page. Default false (= hidden). Turning
	// it ON shows it as pill + icon. The trade-off between the self-hosted
	// principle (= hide the backend from visitors) and brand exposure is left
	// to the site owner.
	ShowCredit bool `yaml:"show_credit,omitempty"`
	// ObserveOnly: monitor mode. When true, all challenge actions are
	// suppressed and only event logging continues (= for the post-install
	// observation phase).
	//
	// Behavior:
	//   - auth_request mode: even when auth_check returns action=challenge/block,
	//     the response ends up action=pass. event payload retains observe_only=1.
	//   - native mode: for requests nginx forwards to the challenge route,
	//     the admin's ServeChallenge skips PoW/CAPTCHA and returns HTML that
	//     redirects to orig_path immediately (= one extra round-trip but
	//     feels like passthrough).
	//
	// Toggle with `unmask-admin apply-preset monitor` (= ObserveOnly=true).
	// Reset back to false when switching to strict / balanced.
	ObserveOnly bool `yaml:"observe_only,omitempty"`
}

// ResolvedPowDifficulty: returns default 18 when 0 / out of range.
func (c Challenge) ResolvedPowDifficulty() int {
	if c.PowDifficulty < 8 || c.PowDifficulty > 24 {
		return 18
	}
	return c.PowDifficulty
}

// Captcha: CAPTCHA provider settings. Non-builtin providers use an external
// siteverify service, so they carry site_key (= shown in HTML) and secret_key
// (= used for server verification).
//
// secret_key is written in plain text to admin.yml (= unmask does not provide
// env-var indirection; protect via file permissions). Even if leaked, impact
// on the site is limited (= the attacker can use the key on their own site,
// but cannot bypass unmask's protection).
type Captcha struct {
	Provider           string  `yaml:"provider,omitempty"` // "builtin" (default) | "turnstile" | "hcaptcha" | "recaptcha"
	TurnstileSiteKey   string  `yaml:"turnstile_site_key,omitempty"`
	TurnstileSecretKey string  `yaml:"turnstile_secret_key,omitempty"`
	HCaptchaSiteKey    string  `yaml:"hcaptcha_site_key,omitempty"`
	HCaptchaSecretKey  string  `yaml:"hcaptcha_secret_key,omitempty"`
	RecaptchaSiteKey   string  `yaml:"recaptcha_site_key,omitempty"`
	RecaptchaSecretKey string  `yaml:"recaptcha_secret_key,omitempty"`
	RecaptchaMinScore  float64 `yaml:"recaptcha_min_score,omitempty"` // reCAPTCHA v3 score threshold. default 0.5
}

type Server struct {
	// Bind: an IP for TCP (= "127.0.0.1" / "0.0.0.0" / a specific IP).
	// For unix domain socket, "unix:/path/to.sock" form. When the "unix:"
	// prefix is detected, Port is ignored and listen happens on the socket
	// file (= no TCP listener). All major reverse proxies (nginx / Apache /
	// Caddy / HAProxy / Envoy / Traefik) support unix-socket upstreams.
	// Benefits: no port collisions, no firewall config, slightly faster than
	// TCP loopback, and OS-level access control via socket file owner/mode.
	Bind     string `yaml:"bind"`
	Port     int    `yaml:"port"`
	BasePath string `yaml:"base_path"`
	// SocketMode: file permission for the unix domain socket. Written as an
	// octal string (= "0660" etc.). Empty → default 0660 (= owner rw,
	// group rw, other none). Group access (= 0660) is required so the
	// nginx worker can read/write the socket.
	SocketMode string `yaml:"socket_mode,omitempty"`
	// SocketGroup: group owner name for the unix domain socket. Empty →
	// default "nginx". If the nginx worker is in the same group it can
	// read/write directly. Override to "apache" / "www-data" etc. when the
	// httpd runs as a different group.
	SocketGroup string `yaml:"socket_group,omitempty"`
	// HostID: name that identifies "which machine produced this record" in a
	// shared DB / aggregated dashboard. Unset → main.go's startup resolves
	// to os.Hostname(). For single-host installs leave empty (= hostname is
	// filled automatically). In shared-DB setups where hostnames collide or
	// change dynamically, pin a fixed name in config.
	HostID string `yaml:"host_id,omitempty"`
	// LogPath: log output destination for unmask-admin itself. Unset / empty
	// → stderr. When combined with logrotate, send SIGHUP from postrotate
	// and the admin re-opens the file fd (= writes to the post-rename inode).
	// We do not use systemd unit StandardOutput=append: (= if systemd holds
	// the fd, the admin cannot handle rotation; instead we use the journal
	// only as a fallback for startup errors).
	LogPath string `yaml:"log_path,omitempty"`
}

// IPGeo: optional IP-geolocation mmdb integration (DB-IP Lite / MaxMind
// GeoLite2 / etc., all consumable via the maxminddb-format reader).
//   mmdb_path     : Country or City DB. Pointing at the City DB also enables
//                   city-level lookup. (e.g., /usr/share/GeoIP/GeoLite2-Country.mmdb).
//                   Unset → no country chart and no country row in popovers.
//   mmdb_asn_path : ASN DB (GeoLite2-ASN.mmdb etc.). Unset → no ASN row.
//   For GeoLite2 the MaxMind license prohibits bundling the binary, so the
//   user downloads it themselves; DB-IP Lite (CC BY 4.0) can be auto-fetched
//   via `unmask-admin install-ipgeo`.
type IPGeo struct {
	MMDBPath    string `yaml:"mmdb_path"`
	MMDBASNPath string `yaml:"mmdb_asn_path"`
}

// NginxLog: data source for the cookie-passage dashboard.
//   enabled    : false → do not render the access_log directive in
//                nginx-rendered.{conf,server.inc}. Dashboard / hunt charts
//                show all zeros, but UDP datagram send/receive cost is zero.
//                Default true. Empty socket_path is effectively disabled too.
//   socket_path: path of the Unix datagram socket the admin binds. Keep in
//                sync with nginx access_log syslog:server=unix:<same path>.
type NginxLog struct {
	Enabled    bool   `yaml:"enabled"`
	SocketPath string `yaml:"socket_path"`
}

// Nginx: input that `unmask-admin render-nginx` uses to generate the nginx config.
//
// Users only need to edit config.yml's nginx.* — no per-file conf editing
// (= no legacy search-bots.conf / honeypot.map / sites.map / secret.conf etc.).
// Search bot UAs and JA4 verdicts are held in preset groups, with group-level
// enable/disable plus the ability to add custom patterns.
//
// Edit boundary:
//   - bootstrap (= not web-editable, install-time ops only): OutputDir / UpstreamAddr
//   - runtime   (= editable from the web): everything else
type Nginx struct {
	// ── bootstrap ────────────────────────────────────────
	OutputDir    string `yaml:"output_dir"`
	UpstreamAddr string `yaml:"upstream_addr"`

	// SeenVersion: admin version at the last time the user saved the settings page.
	// Preset groups with an AddedIn newer than this are treated as
	// "added by a version bump" → default OFF + NEW badge shown. Prevents
	// silent activation. Overwritten with the current version on each save.
	SeenVersion string `yaml:"seen_version,omitempty"`

	// ── runtime ───────────────────────────────────────────
	// Allowlist (IP / CIDR) that passes through challenge / rate_limit (= 4 parallel arrays for the row UI).
	BypassIPs          []string `yaml:"bypass_ips"`
	BypassIPsTitle     []string `yaml:"bypass_ips_title,omitempty"`
	BypassIPsDisabled  []bool   `yaml:"bypass_ips_disabled,omitempty"`
	BypassIPsUpdatedAt []int64  `yaml:"bypass_ips_updated_at,omitempty"`
	// IDs of official IP-range preset groups (= Googlebot / Bingbot / OAI etc.)
	// to keep OFF. Empty → all presets enabled (= default safety net). Group
	// definitions live in nginxconf/iprange.go.
	BypassIPDisabledPresets []string `yaml:"bypass_ip_disabled_presets,omitempty"`
	AdminAllowFrom   []string `yaml:"admin_allow_from"`
	MetricsAllowFrom []string `yaml:"metrics_allow_from"`

	// Preset IDs of trusted LBs. Default is empty (= all disabled, secure default).
	// Pick IDs from the presets in nginxconf/lb_iprange.go to enable. Example:
	//   trusted_lb_presets: [gcp]
	// → trust X-Client-JA4 only on requests from the GCP LB IP range.
	TrustedLBPresets []string `yaml:"trusted_lb_presets,omitempty"`

	// Custom definitions for LBs not in the preset list. Merged in parallel
	// with presets into the effective list. Example:
	//   trusted_lb_extra:
	//     - id: "internal-haproxy"
	//       cidrs: ["10.0.1.0/24"]
	//       header: "$http_x_client_ja4"
	TrustedLBExtra []TrustedLBExtra `yaml:"trusted_lb_extra,omitempty"`

	SearchBots       SearchBotsConfig       `yaml:"search_bots"`
	JA4Verdicts      JA4VerdictsConfig      `yaml:"ja4_verdicts"`
	ChallengeTargets ChallengeTargetsConfig `yaml:"challenge_targets"`
	Honeypot         HoneypotConfig         `yaml:"honeypot"`
	ProtectedPaths   ProtectedPathsConfig   `yaml:"protected_paths"`
	BypassPaths      BypassPathsConfig      `yaml:"bypass_paths"`
	Geo              GeoConfig              `yaml:"geo,omitempty"`
}

// GeoConfig: country-based decision axis, applied in both auth_request mode
// (= admin /authcheck does the lookup live) and native nginx-plugin mode
// (= render-time mmdb walk emits a `geo $remote_addr $unmask_country` block
// into http.inc).  Either way the plugin / module itself does not link
// libmaxminddb — admin is the only consumer of the mmdb file.
//
// Requires IPGeo.MMDBPath to be configured (= mmdb loaded at startup for
// auth_request mode, walked at render time for native mode).  Rule / mmdb
// changes take effect after `unmask-admin render-nginx && nginx -s reload`
// in native mode; auth_request mode reloads the mmdb on settings save.
//
// Model: one rule per country.  Default action for unmatched countries (= the
// long-tail of the world) is `DefaultAction`.  Each rule may also opt the
// country IN or OUT of rate-limit counting independently of its access action.
//
// Action values (= rule-level AND DefaultAction):
//   - ""               : pass-through, no geo intervention (default)
//   - "pass"           : same as "" (explicit allowlist marker for clarity)
//   - "pow_only"
//   - "captcha_only"
//   - "pow_then_captcha"
//   - "deny"           : 403 immediately, no challenge offered
//
// Evaluation order: country runs AFTER `_bv` cookie pass so a visitor who
// already cleared CAPTCHA is not re-blocked by a country list change.
type GeoConfig struct {
	// DefaultAction: applied to countries that do not match any rule.
	// Empty -> "pass" (= blocklist semantics, the common case).
	// Set to a challenge action or "deny" for allowlist semantics
	// (= the matching rules carry "pass" for the few allowed countries).
	DefaultAction string `yaml:"default_action,omitempty"`
	// Rules: per-country overrides.  Index is meaningless for behavior
	// but stable for UI display.  Disabled rules are persisted but skipped
	// at evaluation time.
	Rules []GeoRule `yaml:"rules,omitempty"`
}

// GeoRule: one country override.
type GeoRule struct {
	Country   string `yaml:"country"`              // ISO 3166-1 alpha-2 (upper-case after save)
	Action    string `yaml:"action,omitempty"`     // see GeoConfig docstring; empty = inherit DefaultAction
	Enabled   bool   `yaml:"enabled"`              // false -> rule kept in yaml but skipped at evaluation
	UpdatedAt int64  `yaml:"updated_at,omitempty"` // unix sec, for UI "last changed" timestamps
}

// Geo action constants.  Reuses RateChallenge* values for the challenge
// branches so the surrounding chMode plumbing (= challenge.js / dashboard
// pills) needs no special-case for country triggers.
//
// "skip" (= the no-op action) is named "skip" rather than "pass" because
// "pass" suggested an explicit full whitelist to operators.  In reality this
// action just means "this geo rule does not act; the decision chain continues
// to honeypot / BAN / JA4 / UA as usual."  Visitors from a `skip` country
// can still be challenged by downstream axes.
const (
	GeoActionSkip            = "skip"
	GeoActionPoWOnly         = RateChallengePoWOnly
	GeoActionCaptchaOnly     = RateChallengeCaptchaOnly
	GeoActionPoWThenCaptcha  = RateChallengePoWThenCaptcha
	GeoActionDeny            = RateChallengeDeny
)

// IsValidGeoAction validates an action submitted via form / yaml.  Empty
// is allowed (= inherit DefaultAction at evaluation time).
func IsValidGeoAction(a string) bool {
	switch a {
	case "", GeoActionSkip,
		GeoActionPoWOnly, GeoActionCaptchaOnly,
		GeoActionPoWThenCaptcha, GeoActionDeny:
		return true
	}
	return false
}

// ResolvedDefaultAction: empty -> "skip" (= no country-based intervention
// for the long tail of unmatched countries).
func (g GeoConfig) ResolvedDefaultAction() string {
	if g.DefaultAction == "" {
		return GeoActionSkip
	}
	return g.DefaultAction
}

// LookupRule returns the enabled rule for the given uppercase country code,
// or nil if none / disabled.  Linear scan — rule count is expected to be
// small (= dozens), so building a map is not worth the alloc.
func (g GeoConfig) LookupRule(country string) *GeoRule {
	for i := range g.Rules {
		r := &g.Rules[i]
		if r.Enabled && r.Country == country {
			return r
		}
	}
	return nil
}

// BypassPathsConfig: allowlisted paths (= bypass all unmask checks per path).
//
// Use case: register paths where unmask challenge would break things —
// static / api / health / .well-known etc. Makes it easy to keep the whole
// site under unmask while excluding specific paths.
//
// Scope (= matching access bypasses all features):
//   - JA4 verdict bot detection → passthrough
//   - honeypot → passthrough (= no ban record)
//   - protected paths → passthrough
//   - rate limit (= not counted in the $rate_limit_key map)
//
// site column: empty = applies to all sites. A string = applies only when
// `$unmask_site` equals that value (= in multi-site setups you can scope
// "bypass /api/ only for site=foo").
type BypassPathsConfig struct {
	DisabledPresets []string `yaml:"disabled_presets,omitempty"`
	// 5 parallel arrays: path / title / disabled / updated_at / site
	Extra          []string `yaml:"extra,omitempty"`
	ExtraTitle     []string `yaml:"extra_title,omitempty"`
	ExtraDisabled  []bool   `yaml:"extra_disabled,omitempty"`
	ExtraUpdatedAt []int64  `yaml:"extra_updated_at,omitempty"`
	ExtraSite      []string `yaml:"extra_site,omitempty"`
}

// ProtectedPathsConfig: protected-paths feature. Forces CAPTCHA / PoW / strict
// when a specific path is visited. Difference vs honeypot:
//
//	honeypot       : "if you step on the trap → persistent IP BAN affecting
//	                 every subsequent path"
//	protected path : "visitors hitting here are human-verified; only that
//	                 path is affected"
//
// Designed for real human admins to pass via CAPTCHA (= transparent admin
// gate / important-path protection). The mode column is parallel to the path
// list as part of the 5 parallel arrays.
type ProtectedPathsConfig struct {
	// DisabledPresets: do NOT add omitempty (= once saved, always write even []).
	// nil = "never saved" → all presets OFF (= compat with existing yml).
	// After save, [] / [id] / [id1,id2] explicitly communicates the state.
	DisabledPresets []string `yaml:"disabled_presets"`
	Extra           []string `yaml:"extra,omitempty"`
	ExtraTitle      []string `yaml:"extra_title,omitempty"`
	ExtraDisabled   []bool   `yaml:"extra_disabled,omitempty"`
	ExtraUpdatedAt  []int64  `yaml:"extra_updated_at,omitempty"`
	ExtraMode       []string `yaml:"extra_mode,omitempty"` // "captcha" | "pow" | "strict"
	// DefaultAction: chain to run when a request hits a protected path and
	// challenge fires (= chMode used by challenge.html JS).  Empty =
	// inherit ChallengeTargets.DefaultAction → RateLimit.Default.
	DefaultAction string `yaml:"default_action,omitempty"`
	// PresetAction: per-preset chMode override (preset ID → chain).  Stored
	// now; path-based dispatch wiring is a follow-up.
	PresetAction map[string]string `yaml:"preset_action,omitempty"`
	// ExtraAction: per-custom-row chMode override, aligned by index with
	// Extra.  Same "stored now, wired later" caveat.
	ExtraAction []string `yaml:"extra_action,omitempty"`
}

// HoneypotConfig: honeypot path configuration + persistent BAN list management.
//
// Behavior:
//   1. nginx matches a honeypot path (= /wp-login.php etc.) → $serve_bot_challenge=1
//   2. nginx access_log writes "hp=1 ja4=t13d... ip=1.2.3.4" → the admin
//      receives it on the syslog socket
//   3. admin appends the (ip, ja4) tuple to `ban_file_path` (= TTL=ban_duration)
//   4. nginx module watches ban_file by mtime and exposes $unmask_banned=1
//   5. user picks the behavior in their server block:
//      `if ($unmask_banned = 1) { rewrite ^ /unmask/challenge/ last; }`
//      (= force CAPTCHA) or `return 403;` (= hard ban). The behavior is the
//      conf's responsibility (= unmask only exposes the variable)
type HoneypotConfig struct {
	// Disabled preset groups (= same shape as search-bots etc.).
	DisabledPresets []string `yaml:"disabled_presets,omitempty"`
	// Row-UI 4 parallel slices (= path / title / disabled / updated_at).
	// Honeypot fires BAN on hit with fixed behavior, so there is no mode column.
	// For "force CAPTCHA / PoW" use the separate "protected paths" tab.
	Extra          []string `yaml:"extra,omitempty"`
	ExtraTitle     []string `yaml:"extra_title,omitempty"`
	ExtraDisabled  []bool   `yaml:"extra_disabled,omitempty"`
	ExtraUpdatedAt []int64  `yaml:"extra_updated_at,omitempty"`
	BanDuration    int      `yaml:"ban_duration"`  // seconds. 0 = permanent. default 86400 (= 24h)
	BanFilePath    string   `yaml:"ban_file_path"` // output path for the ban list (= honeypot / manual / all sources). default /etc/unmask/banned.txt
	// DefaultAction: chain to run when a honeypot trip results in a
	// challenge (= chMode used by challenge.html JS).  Empty = inherit
	// ChallengeTargets.DefaultAction → RateLimit.Default.
	DefaultAction string `yaml:"default_action,omitempty"`
	// PresetAction: per-preset action override (preset ID → mode).
	// Path-level resolution (= which preset was tripped) is wired up in a
	// follow-up; the field is stored now so the UI is round-trippable.
	PresetAction map[string]string `yaml:"preset_action,omitempty"`
	// ExtraAction: per-custom-row action override, aligned by index with
	// Extra.  Same "stored now, wired later" caveat.
	ExtraAction []string `yaml:"extra_action,omitempty"`
}

// ChallengeTargetsConfig: which UAs receive a challenge when bot signals fire.
//
//   all              : true → always target regardless of UA (= preset / extra ignored)
//   disabled_presets : list of preset-group IDs to keep OFF
//   extra            : custom UA patterns (= nginx case-insensitive regex)
type ChallengeTargetsConfig struct {
	All             bool     `yaml:"all"`
	DisabledPresets []string `yaml:"disabled_presets"`
	Extra           []string `yaml:"extra"`
	ExtraTitle      []string `yaml:"extra_title,omitempty"`
	ExtraDisabled   []bool   `yaml:"extra_disabled,omitempty"`
	ExtraUpdatedAt  []int64  `yaml:"extra_updated_at,omitempty"`
	// DefaultAction: chain to run when a black-list UA also triggers a JA4
	// bot signal (= "pow_only" / "pow_then_captcha" / "captcha_only" /
	// "deny").  Empty = fall back to rate_limit.default.challenge_mode so
	// existing installs keep their previous behaviour.  Editable from the
	// ua-filter tab.
	DefaultAction string `yaml:"default_action,omitempty"`
	// PresetAction: per-preset action override.  Keys are preset IDs
	// (= nginxconf.ChallengeTargetGroups[i].ID).  An entry overrides
	// DefaultAction when the UA matches that preset's patterns.  Empty
	// value or absent key = inherit DefaultAction.
	PresetAction map[string]string `yaml:"preset_action,omitempty"`
}

// SearchBotsConfig: search-bot UA preset enable/disable + extras.
//
// Extra / ExtraTitle / ExtraDisabled are parallel slices (= aligned by index).
// ExtraTitle is the human-readable label (= same role as preset.Label) that
// explains the pattern's purpose. Examples: "in-house monitoring crawler" /
// "Slack unfurl". Rows with ExtraDisabled[i]=true are not emitted to
// nginx-rendered.conf (= temporary OFF; unlike deletion, the yml history is
// preserved so a single checkbox click re-enables).
//
// yml: extra: [pat] / extra_title: [title] / extra_disabled: [false].
// Compatible with older yml (= no title / disabled): missing values default
// to empty string / false.
type SearchBotsConfig struct {
	DisabledPresets []string `yaml:"disabled_presets"`
	Extra           []string `yaml:"extra"`
	ExtraTitle      []string `yaml:"extra_title,omitempty"`
	ExtraDisabled   []bool   `yaml:"extra_disabled,omitempty"`
	ExtraUpdatedAt  []int64  `yaml:"extra_updated_at,omitempty"` // unix sec. analogous to preset's AddedIn
	// UpstreamDisabled: per-pattern disable list applied to the upstream
	// crawler-user-agents.json auto-rescue.  Patterns listed here will not
	// be auto-passed via the search_ai branch, even if they match a
	// search-engine / ai-crawler / advertising tag.  Edited via the
	// "詳細" modal on the settings UI.
	UpstreamDisabled []string `yaml:"upstream_disabled,omitempty"`
	// UpstreamGroupMode: per-group override mapping that places a category
	// into "white" (auto-pass), "black" (challenge-target), or "none"
	// (ignore).  Only entries that differ from the built-in default are
	// stored.  See classify.DefaultGroupMode for the defaults.
	UpstreamGroupMode map[string]string `yaml:"upstream_group_mode,omitempty"`
	// UpstreamGroupAction: when a group resolves to "black", optionally
	// override the challenge chain for that specific group (= "pow_only" /
	// "pow_then_captcha" / "captcha_only" / "deny").  Empty / absent =
	// inherit ChallengeTargets.DefaultAction.  Stored as a flat map so the
	// YAML stays small and inspectable.
	UpstreamGroupAction map[string]string `yaml:"upstream_group_action,omitempty"`
}

// JA4VerdictsConfig: JA4 verdict preset enable/disable + extras.
//
// Extra plus parallel slices:
//   - Extra            : list holding pattern + verdict + action as a struct
//   - ExtraTitle       : human label in the row UI (= same role as preset.Label)
//   - ExtraDisabled    : temporary OFF flag (= same as UA filter)
//   - ExtraUpdatedAt   : add/update unix sec (= same as UA filter)
// Pattern / Verdict / Action come from Extra[i]; ExtraTitle / Disabled /
// UpdatedAt align by the same index.
type JA4VerdictsConfig struct {
	DisabledPresets []string              `yaml:"disabled_presets"`
	Extra           []JA4VerdictExtraRule `yaml:"extra"`
	ExtraTitle      []string              `yaml:"extra_title,omitempty"`
	ExtraDisabled   []bool                `yaml:"extra_disabled,omitempty"`
	ExtraUpdatedAt  []int64               `yaml:"extra_updated_at,omitempty"`
	// DefaultAction: chain to run when a request hits a JA4 verdict that
	// resolves to action="bot".  Empty = inherit from
	// ChallengeTargets.DefaultAction → RateLimit.Default.ChallengeMode.
	DefaultAction string `yaml:"default_action,omitempty"`
	// PresetAction: per-preset (= JA4VerdictGroups[i].ID) action override.
	// Empty / absent = inherit DefaultAction.
	PresetAction map[string]string `yaml:"preset_action,omitempty"`
	// ExtraAction: per-custom-row action override, aligned by index with
	// Extra.  Empty string in slot i = inherit DefaultAction.
	ExtraAction []string `yaml:"extra_action,omitempty"`
}

// JA4VerdictExtraRule: a custom pattern added via the web UI.
//
// Verdict is a free-form label (= for log / dashboard display). Action is an
// enum that decides behavior ("bot" | "suspect" | "ok").
//
// ID: rename-safe immutable identifier (= used for DB linking). Auto-numbered
// from 100+. After loading an old config.yml (= without the ID column), init
// backfills and saves once.
// TrustedLBExtra: custom definition for an LB not in the preset list.
//   - id     : value used by the $unmask_lb_vendor nginx variable
//              (= lowercase letters + digits + _). Must not collide with preset IDs.
//   - cidrs  : trusted source IP ranges. IPv4 / IPv6 may be mixed.
//   - header : nginx variable this LB places JA4 into (= "$http_x_client_ja4"
//              etc.). Default is "$http_x_client_ja4".
//   - label  : for UI display (= optional).
type TrustedLBExtra struct {
	ID     string   `yaml:"id"`
	Label  string   `yaml:"label,omitempty"`
	CIDRs  []string `yaml:"cidrs"`
	Header string   `yaml:"header,omitempty"`
}

type JA4VerdictExtraRule struct {
	ID      int    `yaml:"id,omitempty"`
	Pattern string `yaml:"pattern"`
	Verdict string `yaml:"verdict"`
	Action  string `yaml:"action"`
}

// SiteConfig: vestige of the old multi-site feature. Not used as of v0.1.
// The struct definition is retained for yml compatibility, but the UI does
// not touch it and render ignores it (= default site only).
//
// Deprecated: multi-site has been removed. Any leftover sites: [...] in yml
// is silently ignored at startup.
type SiteConfig struct {
	ID                  string   `yaml:"id"`
	Hosts               []string `yaml:"hosts"`
	HoneypotUseDefaults bool     `yaml:"honeypot_use_defaults"`
	HoneypotExtra       []string `yaml:"honeypot_extra"`
}

// GlobalConfig: settings-wide knobs that cross axis boundaries (= UA /
// JA4 / honeypot / protected paths).  Lives at the root of settings so the
// "動作モード" tab can drive them without dragging other tabs into shared
// state.
type GlobalConfig struct {
	// Passthrough = monitoring mode.  When true, the admin's serveBotChallenge
	// short-circuits and bounces the user straight back to the original URL
	// without issuing PoW / CAPTCHA.  Useful for staged rollouts: signals
	// are still recorded in events / dashboard, but visitors are never
	// inconvenienced.
	Passthrough bool `yaml:"passthrough,omitempty"`
	// KnownBrowserAction: chain for no-match requests whose UA looks like a
	// real browser (= classify.IsKnownBrowser).  Default "pass" = ordinary
	// operation (no challenge).  Picking pow_* / captcha_only / deny turns
	// this into a Cloudflare-style human gate for genuine visitors too.
	KnownBrowserAction string `yaml:"known_browser_action,omitempty"`
	// UnknownUAAction: chain for no-match requests whose UA is NOT a known
	// browser (= curl / library / empty / oddball).  Default "pass".
	// Picking pow_* / captcha_only / deny gates anything that isn't a real
	// browser without affecting actual visitors.
	UnknownUAAction string `yaml:"unknown_ua_action,omitempty"`
	// DefaultAction: legacy field (= used to mean "no-match action" for
	// every UA).  Kept for one-release backward compat; new installs use
	// KnownBrowserAction / UnknownUAAction.  Removed once existing configs
	// migrate.
	DefaultAction string `yaml:"default_action,omitempty"`
}

// Site acceptance modes (= SiteAcceptanceConfig.Mode).
const (
	SiteModeAuto    = "auto"    // every observed Host is accepted as a site
	SiteModeDefined = "defined" // only Defined sites are "known"; the rest are ghosts
)

// SiteAcceptanceConfig governs how observed sites (= normalized request Host
// values) are treated.  In "auto" mode every Host is accepted silently.  In
// "defined" mode only the listed sites are known; a Host outside the list is
// still recorded as an event, but flagged as a ghost — surfaced in the
// dashboard's ghost report for one-click promotion into Defined.  The same
// shape is intended to extend to hosts later.
type SiteAcceptanceConfig struct {
	// Mode: "auto" (default) | "defined".  Empty / unrecognized -> auto.
	Mode string `yaml:"mode,omitempty"`
	// Defined: the known sites.  Consulted only in "defined" mode.
	Defined []string `yaml:"defined,omitempty"`
}

// ResolvedMode returns the effective mode, defaulting to SiteModeAuto.
func (c SiteAcceptanceConfig) ResolvedMode() string {
	if c.Mode == SiteModeDefined {
		return SiteModeDefined
	}
	return SiteModeAuto
}

// IsGhost reports whether site is a ghost: observed but not in Defined, while
// in "defined" mode.  In "auto" mode nothing is ever a ghost.
func (c SiteAcceptanceConfig) IsGhost(site string) bool {
	if c.ResolvedMode() != SiteModeDefined || site == "" {
		return false
	}
	for _, d := range c.Defined {
		if d == site {
			return false
		}
	}
	return true
}

type Settings struct {
	DB            DB              `yaml:"db"`
	Secret        Secret          `yaml:"secret"`
	Challenge     Challenge       `yaml:"challenge"`
	Server        Server          `yaml:"server"`
	IPGeo         IPGeo           `yaml:"ipgeo"`
	NginxLog      NginxLog        `yaml:"nginx_log"`
	Nginx         Nginx           `yaml:"nginx"`
	RateLimit     RateLimitConfig `yaml:"rate_limit"`
	SharedFeed    SharedFeed      `yaml:"shared_feed,omitempty"`
	FeedServer    FeedServer      `yaml:"feed_server,omitempty"`
	Notifications Notifications   `yaml:"notifications,omitempty"`
	SMTP          SMTP            `yaml:"smtp,omitempty"`
	Global        GlobalConfig    `yaml:"global,omitempty"`
	Sites         SiteAcceptanceConfig `yaml:"sites,omitempty"`
	// EventsRetentionDays: retention days for raw unmask_event rows. Default 90.
	// 0 = retain forever (= prune disabled). Aggregates (= unmask_aggregate)
	// are not affected and persist forever. On admin server startup, a
	// goroutine runs `DELETE FROM unmask_event WHERE date_created < now - N days`
	// idempotently every 24h.
	EventsRetentionDays int `yaml:"events_retention_days,omitempty"`
	// EventsBatchSize: how many raw events to batch per write. Default 100.
	// Once accumulated, run a bulk INSERT (= N rows in one transaction).
	// On high-traffic sites (= >100 events/sec) this reduces DB writes to 1/N.
	EventsBatchSize int `yaml:"events_batch_size,omitempty"`
	// EventsBatchIntervalMs: max latency for raw event writes (milliseconds).
	// Default 1000. At idle, the remaining events flush at this interval.
	// The hunt page live tail shows "up to N ms delay". Smaller = lower
	// latency / more writes.
	EventsBatchIntervalMs int `yaml:"events_batch_interval_ms,omitempty"`
}

// SMTP: optional outbound mail relay. Empty Host = disabled (= all mail
// features skipped). When configured, alert notifications (= in parallel
// with the existing webhook) and password-reset links can be sent.
//
// Authentication is plain (= AUTH PLAIN / LOGIN). Major SMTP relays
// (Gmail / SES / SendGrid / Mailgun) work by entering the app password /
// API key as Username/Password.
//
// StartTLS: true for submission on port 587 etc. (= recommended). Port 465
// (implicit TLS) is a different path, but modern SMTP relays are fine with
// 587+STARTTLS.
type SMTP struct {
	Host               string `yaml:"host,omitempty"`
	Port               int    `yaml:"port,omitempty"`
	Username           string `yaml:"username,omitempty"`
	Password           string `yaml:"password,omitempty"`
	FromAddress        string `yaml:"from_address,omitempty"`
	FromName           string `yaml:"from_name,omitempty"`
	StartTLS           bool   `yaml:"starttls,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"` // for SMTP relays using self-signed certs
}

// SharedFeed: shared BAN feed (= submit / subscribe mechanism for the
// unmask.sh central hub).
//
// Overview:
//   - When submit_enabled is true, the BAN button on the hunt page, with
//     "share" checked, POSTs ip / ja4 / reason / comment to unmask.sh.
//   - When subscribe_enabled is true, feed_url is pulled hourly and
//     /etc/unmask/shared-feed-*.map (= 3 files) is regenerated. It feeds
//     into `$shared_feed_hit` in nginx-rendered.conf; on hit the response
//     is fixed to CAPTCHA (= cannot block).
//   - The token is obtained from the register endpoint on first startup and
//     persisted in settings. It's sent as a header on submit
//     (= for auth / rate-limit / reputation).
//
// privacy:
//   - Submit is **opt-in** (= default false). Terms are stated on LP /feed/.
//   - While terms_accepted_at is 0, submit_enabled is forced to false.
//
// enforcement policy:
//   - Feed entries are always CAPTCHA (= regardless of the central server's
//     judgment, the client does not BAN). Accepts false positives + reduces
//     legal liability.
type SharedFeed struct {
	SubmitEnabled    bool   `yaml:"submit_enabled"`
	SubscribeEnabled bool   `yaml:"subscribe_enabled"`
	Token            string `yaml:"token,omitempty"`
	RegisterURL      string `yaml:"register_url,omitempty"`
	SubmitURL        string `yaml:"submit_url,omitempty"`
	FeedURL          string `yaml:"feed_url,omitempty"`
	LastPulledAt     int64  `yaml:"last_pulled_at,omitempty"`
	Entries          int    `yaml:"entries,omitempty"`
	TermsAcceptedAt  int64  `yaml:"terms_accepted_at,omitempty"`
	// MapDir: output dir for shared-feed-{ipja4,ja4,ip}.map. Empty = Nginx.OutputDir.
	MapDir string `yaml:"map_dir,omitempty"`
}

// DefaultSharedFeed*: unmask.sh hub URLs. Overridable (= for running a
// private hub or pointing test environments at a different endpoint).
const (
	DefaultSharedFeedRegisterURL = "https://unmask.sh/api/feed/register"
	DefaultSharedFeedSubmitURL   = "https://unmask.sh/api/feed/submit"
	DefaultSharedFeedFeedURL     = "https://unmask.sh/dl/feed/banlist.json"
)

// ResolvedRegisterURL: returns the default when empty.
func (s SharedFeed) ResolvedRegisterURL() string {
	if s.RegisterURL == "" {
		return DefaultSharedFeedRegisterURL
	}
	return s.RegisterURL
}

// ResolvedSubmitURL: returns the default when empty.
func (s SharedFeed) ResolvedSubmitURL() string {
	if s.SubmitURL == "" {
		return DefaultSharedFeedSubmitURL
	}
	return s.SubmitURL
}

// ResolvedFeedURL: returns the default when empty.
func (s SharedFeed) ResolvedFeedURL() string {
	if s.FeedURL == "" {
		return DefaultSharedFeedFeedURL
	}
	return s.FeedURL
}

// SubmitActive: submission is allowed only when submit_enabled && terms accepted.
func (s SharedFeed) SubmitActive() bool {
	return s.SubmitEnabled && s.TermsAcceptedAt > 0
}

// FeedServer: unmask.sh hub-side (= aggregation server) settings. Normal
// installs leave Enabled=false (= client mode). Only the hub install
// (= the unmask.sh production) sets Enabled=true to expose endpoints and
// regenerate feed.json via cron.
//
// Roles:
//   - client (default)   : sharedfeed.Client just submits / pulls to an external hub
//   - hub  (Enabled=true): feedserver.Server exposes register / submit endpoints
//                          + cron aggregates submissions and writes feed.json
type FeedServer struct {
	Enabled bool `yaml:"enabled"`

	// DBPath: sqlite file storing submissions and issued tokens.
	// Empty = hub features disabled (= no-op even with Enabled=true).
	DBPath string `yaml:"db_path,omitempty"`

	// FeedPath: output path for the feed.json generated by cron.
	// Empty = "/var/lib/unmask/feed.json". Distribution is done separately
	// by nginx static file serving (= the hub server only generates the file).
	FeedPath string `yaml:"feed_path,omitempty"`

	// JudgeMode: how to decide if a submission is promoted to a FeedEntry.
	//   "heuristic_only"  - heuristic only
	//   "ai_only"         - AI judge only (= AIEndpoint required)
	//   "and"             - heuristic AND AI both 1 (= strict)
	//   "or"              - either is 1 (= lenient)
	//   "ai_primary"      - prefer AI; fall back to heuristic if AI unavailable
	// Empty defaults to "heuristic_only".
	JudgeMode string `yaml:"judge_mode,omitempty"`

	// HeuristicMinReports: how many distinct installs must report the same
	// IP+JA4 before it is promoted to the feed. 0 = 1 (= single report; for
	// debug). Default 3.
	HeuristicMinReports int `yaml:"heuristic_min_reports,omitempty"`

	// ExpiryDays: lifetime in days for a feed entry. Drops from feed.json
	// once N days have passed since the last submission. 0 = 30 days.
	ExpiryDays int `yaml:"expiry_days,omitempty"`

	// AIEndpoint / AIModel / AIKey: configure to enable AI judge. Empty
	// AIEndpoint skips AI judge (= even when JudgeMode is ai_*, falls back
	// to heuristic).
	AIEndpoint string `yaml:"ai_endpoint,omitempty"`
	AIModel    string `yaml:"ai_model,omitempty"`
	AIKey      string `yaml:"ai_key,omitempty"`
}

// ResolvedFeedPath: returns the default when empty.
func (f FeedServer) ResolvedFeedPath() string {
	if f.FeedPath == "" {
		return "/var/lib/unmask/feed.json"
	}
	return f.FeedPath
}

// ResolvedJudgeMode: defaults to heuristic_only when empty.
func (f FeedServer) ResolvedJudgeMode() string {
	switch f.JudgeMode {
	case "heuristic_only", "ai_only", "and", "or", "ai_primary":
		return f.JudgeMode
	}
	return "heuristic_only"
}

// ResolvedMinReports: returns 1 for 0, otherwise the value as-is.
func (f FeedServer) ResolvedMinReports() int {
	if f.HeuristicMinReports <= 0 {
		return 1
	}
	return f.HeuristicMinReports
}

// ResolvedExpiryDays: returns 30 when 0.
func (f FeedServer) ResolvedExpiryDays() int {
	if f.ExpiryDays <= 0 {
		return 30
	}
	return f.ExpiryDays
}

// Active: true only when Enabled and DBPath is set (= OK to start the server).
func (f FeedServer) Active() bool {
	return f.Enabled && strings.TrimSpace(f.DBPath) != ""
}

// Notifications: external webhook notifications (= Slack / Discord / generic).
type Notifications struct {
	Disabled            bool   `yaml:"disabled,omitempty"`
	URL                 string `yaml:"url,omitempty"`
	Format              string `yaml:"format,omitempty"`              // "slack" | "discord" | "generic"
	SiteLabel           string `yaml:"site_label,omitempty"`          // optional label shown in notifications (e.g., "blog-jp")
	BanEvents           bool   `yaml:"ban_events,omitempty"`          // notify on honeypot / manual ban
	ChallengeBurst      bool   `yaml:"challenge_burst,omitempty"`     // notify when the 5min threshold is exceeded
	BurstThresholdPer5m int    `yaml:"burst_threshold_per_5m,omitempty"` // 0 = disabled
}

// RateLimitConfig: rate-limit settings. Introduced in v0.1 (= 2026-05-10).
//
// Behavior:
//   - native mode: nginx-rendered.conf auto-renders `limit_req_zone` +
//     `limit_req` in server { } + `error_page 429 = @unmask_rate_challenge;`.
//     Users just paste the unmask block into server { } and rate-limit is wired up.
//   - auth_request / forward-auth mode: counted by the admin's sliding-window
//     counter (= internal/ratelimit). Works with any httpd
//     (nginx / Apache / Caddy / Envoy).
//
// Zone resolution order:
//   1. Scan Zones in index order. Adopt the first zone whose PathPatterns
//      prefix-matches.
//   2. If none match, adopt the Default zone.
//
// challenge_mode (= behavior for clients over the threshold):
//   - "captcha_only"      : straight to CAPTCHA (= compat with v0.1 behavior)
//   - "pow_only"          : PoW only. Lightweight, but robust bots pass through
//   - "pow_then_captcha"  : escalate to CAPTCHA on PoW failure. Chain in late v0.1.
//   - "deny"              : no challenge; immediately 403 block (= for API /
//                            paths dedicated to known bots)
type RateLimitConfig struct {
	Default RateZone   `yaml:"default"`
	Zones   []RateZone `yaml:"zones,omitempty"`
	// Key: which fingerprint to count requests against.
	//   "ip"     : $binary_remote_addr only (= default; behaves like classic limit_req)
	//   "ja4"    : $effective_ja4 only (= one bucket per TLS fingerprint; catches
	//              botnets that rotate through many IPs but share a JA4)
	//   "ip+ja4" : "ip|ja4" compound (= narrowest. Two distinct browsers behind
	//              one NAT IP are counted separately)
	// Empty -> "ip" (= back-compat with installs that pre-date this field).
	Key string `yaml:"key,omitempty"`
}

// Rate-limit key kinds.
const (
	RateLimitKeyIP      = "ip"
	RateLimitKeyJA4     = "ja4"
	RateLimitKeyIPAndJA4 = "ip+ja4"
)

// IsValidRateLimitKey: validate the key kind submitted via form / yaml.
func IsValidRateLimitKey(k string) bool {
	switch k {
	case RateLimitKeyIP, RateLimitKeyJA4, RateLimitKeyIPAndJA4:
		return true
	}
	return false
}

// ResolvedKey: returns the configured Key, defaulting to "ip" when empty.
func (rl RateLimitConfig) ResolvedKey() string {
	if rl.Key == "" {
		return RateLimitKeyIP
	}
	return rl.Key
}

// RateZone: definition of a single rate-limit zone.
//
// Name: nginx `limit_req_zone` name syntax (= alnum + "_"). Default zone
// may be empty.
// PathPatterns: simple prefix match. e.g. "/api/" matches "/api/foo".
//   - empty list = applies to all paths (= meant for use as Default).
//   - multiple entries: a match against any one selects this zone.
// WindowSec: 0 → 60 (= 1-minute window).
// ChallengeMode: empty → parent (= settings-wide) default "captcha_only".
type RateZone struct {
	Name           string   `yaml:"name,omitempty"`
	RequestsPerMin int      `yaml:"requests_per_min"`
	Burst          int      `yaml:"burst"`
	WindowSec      int      `yaml:"window_sec,omitempty"`
	PathPatterns   []string `yaml:"path_patterns,omitempty"`
	ChallengeMode  string   `yaml:"challenge_mode,omitempty"`
}

// Challenge-mode constants for rate-limit.
const (
	RateChallengeCaptchaOnly    = "captcha_only"
	RateChallengePoWOnly        = "pow_only"
	RateChallengePoWThenCaptcha = "pow_then_captcha"
	RateChallengeDeny           = "deny"
)

// IsValidRateChallengeMode: validates challenge_mode values from form/yaml.
func IsValidRateChallengeMode(mode string) bool {
	switch mode {
	case RateChallengeCaptchaOnly, RateChallengePoWOnly, RateChallengePoWThenCaptcha, RateChallengeDeny:
		return true
	}
	return false
}

// ResolvedWindowSec: returns 60 when 0 (= 1-minute window default).
func (z RateZone) ResolvedWindowSec() int {
	if z.WindowSec <= 0 {
		return 60
	}
	return z.WindowSec
}

// ResolvedChallengeMode: returns pow_then_captcha (= recommended chain) when empty.
func (z RateZone) ResolvedChallengeMode() string {
	if !IsValidRateChallengeMode(z.ChallengeMode) {
		return RateChallengePoWThenCaptcha
	}
	return z.ChallengeMode
}

// MatchPath: whether the zone's PathPatterns prefix-match the path.
// Empty PathPatterns → true (= applies to all paths / for the Default zone).
func (z RateZone) MatchPath(path string) bool {
	if len(z.PathPatterns) == 0 {
		return true
	}
	for _, p := range z.PathPatterns {
		if p == "" {
			continue
		}
		if len(path) >= len(p) && path[:len(p)] == p {
			return true
		}
	}
	return false
}

// ResolveZone: returns the zone that corresponds to path. Scans Zones in
// order and returns the first one whose PathPatterns match. Falls back to
// Default if none match.
func (c RateLimitConfig) ResolveZone(path string) RateZone {
	for _, z := range c.Zones {
		if z.MatchPath(path) {
			return z
		}
	}
	return c.Default
}

func defaults() Settings {
	return Settings{
		EventsRetentionDays:   90,
		EventsBatchSize:       100,
		EventsBatchIntervalMs: 1000,
		DB: DB{
			Driver:     "sqlite",
			SQLitePath: "/var/lib/unmask/unmask.sqlite",
			MariaDB: MariaDB{
				Host: "127.0.0.1", Port: 3306,
				User: "unmask", Database: "unmask",
			},
		},
		Challenge: Challenge{
			// Legacy umbrella; kept so config files that only set cookie_seconds
			// still control both kinds.  New installs prefer the per-kind values
			// below (= PoW shorter than CAPTCHA, since PoW is auto-only proof).
			CookieSeconds:             86400 * 3,
			PowCookieValidSeconds:     86400 * 3, // 3 days — automatic proof, refresh more often
			CaptchaCookieValidSeconds: 86400 * 7, // 7 days — human-effort proof, keep longer
			CaptchaScoreThreshold:     0.5,
			DebugRateLimitPer5Min:     20,
			Theme:                     "default",
			CaptchaProvider: Captcha{
				Provider:          "builtin",
				RecaptchaMinScore: 0.5,
			},
		},
		RateLimit: RateLimitConfig{
			// The Default zone is path-agnostic / applies to all traffic.
			// 100r/m + burst 50. Challenge mode is pow_then_captcha
			// (= recommended chain): stall with PoW + verify with CAPTCHA.
			// Legitimate users typically only need PoW.
			Default: RateZone{
				Name:           "unmask_rate",
				RequestsPerMin: 100,
				Burst:          50,
				WindowSec:      60,
				ChallengeMode:  RateChallengePoWThenCaptcha,
			},
		},
		Server: Server{
			Bind:     "127.0.0.1",
			Port:     9477,
			BasePath: "/unmask",
			LogPath:  "/var/log/unmask/admin.log",
		},
		NginxLog: NginxLog{
			Enabled:    true,
			SocketPath: "/run/unmask/log.sock",
		},
		// IPGeo default points at the unmask-scoped install path that
		// `unmask-admin install-ipgeo` writes to.  The file is NOT bundled
		// (= DB-IP Lite is dl on demand); if it doesn't exist, ipgeo.Reader
		// quietly stays in "no DB" mode and the geo axis short-circuits to
		// silent.  Once install-ipgeo runs, admin's next reload picks it up.
		IPGeo: IPGeo{
			MMDBPath: "/var/lib/unmask/ipgeo/dbip-country.mmdb",
			// ASN DB is optional but defaults to the DB-IP managed path so
			// the network tab's ASN radio pre-selects "DB-IP".  Users who
			// pick "none" get this cleared on save.
			MMDBASNPath: "/var/lib/unmask/ipgeo/dbip-asn.mmdb",
		},
		SharedFeed: SharedFeed{
			SubmitEnabled:    false,
			SubscribeEnabled: false,
			RegisterURL:      DefaultSharedFeedRegisterURL,
			SubmitURL:        DefaultSharedFeedSubmitURL,
			FeedURL:          DefaultSharedFeedFeedURL,
		},
		Nginx: Nginx{
			OutputDir:    "/etc/unmask",
			UpstreamAddr: "127.0.0.1:9477",
			SeenVersion:  "v0.1", // for old-yml compat (= initialized here when the field is missing)
			// AdminAllowFrom defaults to empty: avoids silently locking down
			// existing installs (= deployments behind an LB) to loopback only.
			// The install wizard forces a non-empty value. The nginx render
			// path falls back to loopback via defaultAllow.
			AdminAllowFrom:   nil,
			MetricsAllowFrom: nil,
			ChallengeTargets: ChallengeTargetsConfig{
				// Default = challenge every UA (= safe default for self-hosted
				// setups that prioritize bot exclusion). Search / AI bots are
				// reliably bypassed via the other path (= SearchBots + official
				// IP range two-tier rescue), so SEO incidents don't occur.
				All: true,
				// preset list is unused when All=true, but the historical
				// disabled set is preserved so toggling All OFF works.
				DisabledPresets: []string{
					"cli", "python_libs", "node_libs", "go_libs",
					"java_libs", "headless", "empty",
				},
			},
			Honeypot: HoneypotConfig{
				// All presets OFF by default. Treating a real path on an
				// existing site (e.g., /wp-login.php in active use) as a
				// honeypot would CAPTCHA legitimate users, so the user
				// explicitly enables only groups they've confirmed are
				// "paths we never touch in our environment".
				DisabledPresets: []string{
					"wordpress", "secrets", "cms-admin", "shell", "cgi-tomcat", "scan-paths",
				},
				BanDuration: 86400, // 24h
				BanFilePath: "/etc/unmask/banned.txt",
			},
		},
	}
}

// ResolvePath: resolves in order of the -config arg / UNMASK_CONFIG /
// default paths and returns the result. Empty string = no config file
// (= runs with default values).
func ResolvePath(path string) string {
	if path != "" {
		return path
	}
	if p := os.Getenv("UNMASK_CONFIG"); p != "" {
		return p
	}
	for _, p := range defaultPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// Load reads the config file (path or auto-detected) and overlays it on top
// of defaults. If no config file is found, defaults are returned.
//
// Unset secrets are filled with per-session random values (= they change on
// every startup, so production should write them in config. This is for the
// "starts up and just works" experience).
func Load(path string) (Settings, error) {
	s := defaults()
	resolved := ResolvePath(path)
	if resolved != "" {
		raw, err := os.ReadFile(resolved)
		if err != nil {
			return s, fmt.Errorf("read %s: %w", resolved, err)
		}
		if err := yaml.Unmarshal(raw, &s); err != nil {
			return s, fmt.Errorf("parse %s: %w", resolved, err)
		}
	}
	if s.Secret.BVSecret == "" {
		s.Secret.BVSecret = randomHex(24)
	}
	if s.Secret.CaptchaSecretBase == "" {
		s.Secret.CaptchaSecretBase = randomHex(24)
	}
	// backward compat: if old yaml has cookie_days but lacks cookie_seconds,
	// migrate once (= save writes cookie_seconds back alone). However, when
	// defaults() seeds CookieSeconds=259200 and yaml overrides only
	// cookie_days, we can't detect it (= yaml.Unmarshal does not touch
	// CookieSeconds), so detect "yaml has cookie_days and differs from defaults"
	// and migrate.
	if s.Challenge.CookieDays > 0 && s.Challenge.CookieSeconds == 86400*3 {
		// If CookieDays is set explicitly, prefer it (= migrate even if it
		// matches defaults' 3; harmless because 86400*3 → 86400*3 is a no-op).
		s.Challenge.CookieSeconds = s.Challenge.CookieDays * 86400
	}
	// CookieDays is legacy. CookieSeconds is the sole canonical value. omitempty on save.
	s.Challenge.CookieDays = 0
	BackfillExtraVerdictIDs(&s)
	return s, nil
}

// BrowserCookieMaxAgeSeconds is the fixed Max-Age set on _bv cookies sent
// to browsers.  Decoupled from the server-side validity window so that
// changes to PowCookieValidSeconds / CaptchaCookieValidSeconds take effect on
// the very next request without waiting for in-flight cookies to expire.
// 365 days = "practically permanent"; server-side `today - day` check is the
// real gate.
const BrowserCookieMaxAgeSeconds = 365 * 86400

// CookieMaxAgeSeconds: seconds passed to the cookie's Max-Age.  Fixed at
// BrowserCookieMaxAgeSeconds (= server validity window decides effective TTL).
func (c Challenge) CookieMaxAgeSeconds() int { return BrowserCookieMaxAgeSeconds }

// PowCookieValidSecondsResolved: PowCookieValidSeconds if set, else
// CookieSeconds (= legacy single knob), else 3 days.
func (c Challenge) PowCookieValidSecondsResolved() int {
	if c.PowCookieValidSeconds > 0 {
		return c.PowCookieValidSeconds
	}
	if c.CookieSeconds > 0 {
		return c.CookieSeconds
	}
	return 86400 * 3
}

// CaptchaCookieValidSecondsResolved: CaptchaCookieValidSeconds if set, else
// CookieSeconds, else 3 days.
func (c Challenge) CaptchaCookieValidSecondsResolved() int {
	if c.CaptchaCookieValidSeconds > 0 {
		return c.CaptchaCookieValidSeconds
	}
	if c.CookieSeconds > 0 {
		return c.CookieSeconds
	}
	return 86400 * 3
}

// BackfillExtraVerdictIDs: auto-numbering for ID-based linking. For existing
// extra rules with ID==0 (= old config / just-added rows), assigns sequential
// IDs starting at 100. Uses max(existing ID) + 1 to avoid collisions (= same
// logic as AssignExtraID, mirrored inside settings to avoid an nginxconf
// dependency).
//
// No side effects (= the caller decides whether to Save). Called both after
// startup Load and from the settings save path.
func BackfillExtraVerdictIDs(s *Settings) {
	if s == nil {
		return
	}
	extras := s.Nginx.JA4Verdicts.Extra
	maxID := 99
	for _, e := range extras {
		if e.ID > maxID {
			maxID = e.ID
		}
	}
	for i := range extras {
		if extras[i].ID == 0 {
			maxID++
			extras[i].ID = maxID
		}
	}
}

// Save writes the settings to path atomically. Existing file comments are
// lost (= yaml.v3 marshal does not preserve comments). To compensate, prepend
// a header stating "managed by the web UI".
//
// atomic write: write to a temp file in the same dir → fsync → rename
// (= POSIX atomic). Permission is 0600 (= secrets are included).
// MarshalYAML serializes a Settings as the canonical yaml form (= the same
// representation Save writes to disk minus the header comment).  Used by the
// audit / diff path to capture before/after snapshots.
func MarshalYAML(s Settings) (string, error) {
	body, err := yaml.Marshal(&s)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// LoadFromYAML parses a yaml string into Settings.  Counterpart of MarshalYAML
// for the audit-rollback path.  Starts from defaults() so missing fields stay
// at sane defaults (matches the Load() contract).
func LoadFromYAML(body string) (Settings, error) {
	s := defaults()
	if err := yaml.Unmarshal([]byte(body), &s); err != nil {
		return Settings{}, err
	}
	return s, nil
}

func Save(s Settings, path string) error {
	if path == "" {
		return fmt.Errorf("save: path is empty")
	}
	body, err := yaml.Marshal(&s)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	header := []byte(
		"# unmask config (= managed by unmask-admin web UI; do not edit while admin running)\n" +
			"# Comments authored right after install are lost when saved via the web.\n" +
			"# Bootstrap values (= db/secret/server/...) are not web-editable; write them manually at install time only.\n\n",
	)
	body = append(header, body...)

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
