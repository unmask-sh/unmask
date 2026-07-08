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
//	  pow_cookie_valid_seconds: 604800       # 7 days
//	  captcha_cookie_valid_seconds: 1209600  # 14 days
//	  debug_rate_limit_per_5min: 20
//	  challenge_html_path: ""            # empty → use the embedded copy
//	  captcha:
//	    provider: builtin
//	    builtin_score_threshold: 0.5     # behavioral pass threshold (builtin only)
//	server:
//	  bind: 127.0.0.1
//	  port: 9477
//	  base_path: /unmask                 # URL prefix for the admin app
//
// Authentication uses the internal user DB (= unmask_user table). On first
// startup an admin/superadmin user is auto-created and a random password is
// printed to the log exactly once. The CLI can also manage users:
// `unmask user create / reset-password / set-role / delete`.
package settings

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/privacypass"
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

// ChallengeConfig: multi-site Default + Sites wrapper around a ChallengeValues
// record.  In v2 each site either uses Default verbatim (= no entry in Sites)
// or carries a complete self-contained ChallengeValues record (= a full set,
// no field-level inheritance).  Resolve(site) returns the effective record.
type ChallengeConfig struct {
	Default ChallengeValues            `yaml:"default"`
	Sites   map[string]ChallengeValues `yaml:"sites,omitempty"`
}

// JA4 trust at the admin / HTTP layer is gated by the LB CIDR list alone
// (= settings.Nginx.TrustedLBPresets / TrustedLBExtra plus the loopback
// default).  An X-Client-JA4 header is honored iff the connection peer falls
// inside that list; no separate on/off knob exists.  Configuring at least
// one trusted LB CIDR turns the trust on; leaving the list empty (loopback
// only) means only nginx (= the local proxy) can supply JA4, which is the
// shape every native-mode install ends up in by default.

// Resolve returns the ChallengeValues for the given site.  When site has an
// entry in Sites the entry is returned verbatim (= no merge with Default,
// even if a field is the zero value -- that's intentional per the v2 design).
// Otherwise Default is returned verbatim.
func (c ChallengeConfig) Resolve(site string) ChallengeValues {
	if v, ok := c.Sites[site]; ok && !v.Disabled {
		return v
	}
	return c.Default
}

// ChallengeValues: one complete challenge record.  This carries the same
// fields the single-set Challenge struct did before multi-site v2 -- a full
// set of knobs (PoW difficulty, cookie windows, CAPTCHA provider, ...) that
// a site either inherits via Default or fully owns via Sites[<host>].
type ChallengeValues struct {
	// PowCookieValidSeconds: server-side validity window for _bv issued via
	// the PoW path (= 4-segment "pow2" cookie).  Browser-side cookie Max-Age
	// is fixed at 365 days so a server-side window change takes effect on the
	// next request.  0 falls through to the hard default in
	// PowCookieValidSecondsResolved.
	PowCookieValidSeconds int `yaml:"pow_cookie_valid_seconds,omitempty"`
	// CaptchaCookieValidSeconds: same but for _bv issued via the CAPTCHA path
	// (= 3-segment HMAC cookie).
	CaptchaCookieValidSeconds int    `yaml:"captcha_cookie_valid_seconds,omitempty"`
	DebugRateLimitPer5Min     int    `yaml:"debug_rate_limit_per_5min"`
	ChallengeHTMLPath         string `yaml:"challenge_html_path"`
	// PublicTestPages: /unmask/test/ + /unmask/test/{reset-cookie,force-pow,force-captcha}
	// **publicly**. Default false (= 404). /unmask/admin/test/ is always
	// available to logged-in users regardless of this flag. Turning public
	// access ON exposes cookie-clear / PoW / CAPTCHA test pages to anyone,
	// so it should be enabled only for demos or CI smoke tests.
	PublicTestPages bool `yaml:"public_test_pages,omitempty"`
	// PublicTestPagesPassword: optional shared password that gates the public
	// test pages via HTTP Basic Auth.  When PublicTestPages is true and this
	// is non-empty, /unmask/test/* requires Basic Auth (= the visitor's
	// browser pops the standard "site requests authentication" dialog).
	// Any username is accepted; only the password is checked.  Empty value
	// (= default) leaves the pages open to anyone once PublicTestPages is on.
	PublicTestPagesPassword string `yaml:"public_test_pages_password,omitempty"`
	// CAPTCHA provider: "builtin" (= unmask's standard behavioral) | "turnstile" |
	// "hcaptcha" | "recaptcha" (= reCAPTCHA v3). Default is "builtin".
	CaptchaProvider Captcha `yaml:"captcha,omitempty"`
	// Challenge-page theme. "default" | "cat" etc. Must match the handler-side
	// allowlist (= challengeThemes). Invalid / empty values fall back to "auto"
	// (= follow the visitor's OS), the out-of-the-box default.
	Theme string `yaml:"theme,omitempty"`
	// CustomColors: optional per-theme background + text overrides that recolor a
	// built-in theme to the site's palette ("match my site colors").  Keyed by
	// theme name (default / dark / terminal / paper / cat); each entry recolors
	// that theme's body / spinner / captcha / input / button from the two colors
	// while the theme keeps its structure (fonts, art, scanlines).  "auto" is NOT
	// keyed here -- it composes the default entry (OS light) and the dark entry
	// (OS dark) at render time.  Colors are validated as hex (#rgb / #rrggbb /
	// #rrggbbaa); an invalid or half-set entry is ignored (= built-in colors).
	CustomColors map[string]ChallengeThemeColors `yaml:"custom_colors,omitempty"`
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
	//   - forward-auth mode: even when auth_check returns action=challenge/block,
	//     the response ends up action=pass. event payload retains observe_only=1.
	//   - native mode: for requests nginx forwards to the challenge route,
	//     the admin's ServeChallenge skips PoW/CAPTCHA and returns HTML that
	//     redirects to orig_path immediately (= one extra round-trip but
	//     feels like passthrough).
	//
	// Toggle with `unmask apply-preset monitor` (= ObserveOnly=true).
	// Reset back to false when switching to strict / balanced.
	ObserveOnly bool `yaml:"observe_only,omitempty"`
	// Disabled: when true on a Sites[<host>] entry, Resolve(site) returns
	// Default instead of this record.  Used by the admin UI's override
	// toggle so the operator can flip an override off without losing the
	// carefully-edited values stored in the entry.  Default zero (= override
	// enabled) keeps pre-existing per-site entries effective.
	Disabled bool `yaml:"disabled,omitempty"`
}

// ChallengeThemeColors is one theme's operator-set background + text override.
type ChallengeThemeColors struct {
	Bg   string `yaml:"bg,omitempty"`
	Text string `yaml:"text,omitempty"`
}

// CustomColorsFor returns the validated (bg, text) override for the named theme,
// or ("", "") when there is no override or either color is invalid.  Both colors
// must be valid hex for the pair to apply, so the page never renders with one
// custom color and one built-in.
func (c ChallengeValues) CustomColorsFor(theme string) (bg, text string) {
	p, ok := c.CustomColors[theme]
	if !ok {
		return "", ""
	}
	if IsValidHexColor(p.Bg) && IsValidHexColor(p.Text) {
		return p.Bg, p.Text
	}
	return "", ""
}

// IsValidHexColor reports whether s is a CSS hex color (#rgb / #rgba / #rrggbb /
// #rrggbbaa).  Gate for operator-supplied challenge colors before they reach the
// page CSS so an injected value can never carry CSS-breaking characters.
func IsValidHexColor(s string) bool {
	if len(s) == 0 || s[0] != '#' {
		return false
	}
	h := s[1:]
	switch len(h) {
	case 3, 4, 6, 8:
	default:
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ResolvedPowDifficulty: returns default 18 when 0 / out of range.
func (c ChallengeValues) ResolvedPowDifficulty() int {
	if c.PowDifficulty < 8 || c.PowDifficulty > 24 {
		return 18
	}
	return c.PowDifficulty
}

// Branding: multi-site Default + Sites wrapper around a BrandingValues
// record.  Same shape as ChallengeConfig: a site either inherits Default
// verbatim (= no entry in Sites) or carries a complete BrandingValues
// record (= every field set, no field-level merge with Default).
//
// All operator-facing fields are LANGUAGE-AGNOSTIC (= a logo image, a short
// brand string).  Visitor-facing copy lives in challenge.js as a fixed set
// of presets the operator picks from -- that way ja/en stays consistent
// regardless of the visitor's browser locale.
//
// There is intentionally no "enabled" toggle: leaving the identity fields
// blank already produces the same end result (visitor sees the copy preset
// only, no logo / name / footer), so the toggle was a redundant control.
type Branding struct {
	Default BrandingValues            `yaml:"default"`
	Sites   map[string]BrandingValues `yaml:"sites,omitempty"`
}

// Resolve returns the BrandingValues for the given site.  When site has an
// entry in Sites the entry is returned verbatim (no merge with Default).
// Otherwise Default is returned verbatim.
func (b Branding) Resolve(site string) BrandingValues {
	if v, ok := b.Sites[site]; ok && !v.Disabled {
		return v
	}
	return b.Default
}

// BrandingValues: per-site identity shown on the challenge page so visitors
// can recognise "this is operated by <site>" instead of feeling like a
// 3rd-party security tool hijacked the browser.  The defaults ("Verifying
// your browser…") triggered a recurring "is my browser infected?" question
// from real users; a logo + site name + softer copy preset cuts that
// confusion.
type BrandingValues struct {
	// LogoPath: absolute path on disk to the uploaded logo file (PNG / JPEG /
	// SVG). Empty = no logo. Served via /branding/logo with Content-Type set
	// from the file extension. SVGs are sanitized at upload time (= <script>
	// / on*= / <foreignObject> / external href stripped).
	LogoPath string `yaml:"logo_path,omitempty"`
	// SiteName: short brand string substituted into {site_name} placeholders
	// in the preset copy. Plain text; HTML-escaped at render time.
	SiteName string `yaml:"site_name,omitempty"`
	// FooterText: optional small text below the challenge content (e.g.
	// "Operated by ACME"). Plain text; HTML-escaped at render time.
	FooterText string `yaml:"footer_text,omitempty"`
	// CopyPreset: which copy preset to apply to the challenge page strings.
	// "friendly" (= default / reassurance-leaning) | "neutral" (= status-quo
	// compatible) | "minimal" (= short text). Empty / unknown → "friendly".
	CopyPreset string `yaml:"copy_preset,omitempty"`
	// Deny page design (rate-limit "retry" deny + ban "blocked" deny), part of
	// this site's appearance so it follows the same per-site Default/Sites
	// resolution as the logo / site name.  Theme: "" / auto / light / dark;
	// copy preset: "" (inherit this record's CopyPreset) / friendly / neutral /
	// minimal; colors: per-theme bg+text keyed by "light" / "dark" ("auto"
	// composes both via a CSS media query).  rate and ban are independent.
	DenyRateTheme      string                          `yaml:"deny_rate_theme,omitempty"`
	DenyRateCopyPreset string                          `yaml:"deny_rate_copy_preset,omitempty"`
	DenyRateColors     map[string]ChallengeThemeColors `yaml:"deny_rate_colors,omitempty"`
	DenyBanTheme       string                          `yaml:"deny_ban_theme,omitempty"`
	DenyBanCopyPreset  string                          `yaml:"deny_ban_copy_preset,omitempty"`
	DenyBanColors      map[string]ChallengeThemeColors `yaml:"deny_ban_colors,omitempty"`
	// Disabled: when true, Resolve(site) returns the Default record even
	// though this entry exists.  Used to express "operator turned override
	// off but wants the carefully-edited values kept for next time" so the
	// admin UI's checkbox toggle does not destroy work.  Default zero
	// (= override enabled) keeps pre-existing per-site entries effective.
	Disabled bool `yaml:"disabled,omitempty"`
}

// CopyPreset values (= the allowlist).
const (
	BrandingPresetFriendly = "friendly"
	BrandingPresetNeutral  = "neutral"
	BrandingPresetMinimal  = "minimal"
)

// IsValidBrandingPreset: allowlist check used by the save handler and
// the challenge-page serve. Empty falls back to friendly.
func IsValidBrandingPreset(p string) bool {
	switch p {
	case BrandingPresetFriendly, BrandingPresetNeutral, BrandingPresetMinimal:
		return true
	}
	return false
}

// ResolvedCopyPreset: returns CopyPreset clamped to a known value, or the
// friendly default if unset / invalid.
func (b BrandingValues) ResolvedCopyPreset() string {
	if IsValidBrandingPreset(b.CopyPreset) {
		return b.CopyPreset
	}
	return BrandingPresetFriendly
}

// deny page design resolution (per kind).  Theme defaults to "auto"; the copy
// preset falls back to this record's challenge CopyPreset; colors return
// ("","") unless both halves of the pair are valid hex.
func resolvedDenyTheme(t string) string {
	if IsValidDenyTheme(t) {
		return t
	}
	return DenyThemeAuto
}

func denyColorsFor(m map[string]ChallengeThemeColors, name string) (bg, text string) {
	p, ok := m[name]
	if ok && IsValidHexColor(p.Bg) && IsValidHexColor(p.Text) {
		return p.Bg, p.Text
	}
	return "", ""
}

func (b BrandingValues) ResolvedDenyRateTheme() string { return resolvedDenyTheme(b.DenyRateTheme) }
func (b BrandingValues) ResolvedDenyBanTheme() string  { return resolvedDenyTheme(b.DenyBanTheme) }

func (b BrandingValues) DenyRateColorsFor(name string) (bg, text string) {
	return denyColorsFor(b.DenyRateColors, name)
}
func (b BrandingValues) DenyBanColorsFor(name string) (bg, text string) {
	return denyColorsFor(b.DenyBanColors, name)
}

// ResolvedDenyRateCopyPreset / ...Ban: the deny page's wording tone, set
// explicitly per kind (friendly default).  Unlike before, the deny pages do NOT
// inherit the challenge copy preset -- each of challenge / deny / ban carries
// its own tone so there is no hidden cross-page coupling.
func (b BrandingValues) ResolvedDenyRateCopyPreset() string {
	if IsValidBrandingPreset(b.DenyRateCopyPreset) {
		return b.DenyRateCopyPreset
	}
	return BrandingPresetFriendly
}
func (b BrandingValues) ResolvedDenyBanCopyPreset() string {
	if IsValidBrandingPreset(b.DenyBanCopyPreset) {
		return b.DenyBanCopyPreset
	}
	return BrandingPresetFriendly
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
	Provider string `yaml:"provider,omitempty"` // "builtin" (default) | "turnstile" | "hcaptcha" | "recaptcha"
	// BuiltinScoreThreshold: 0.0-1.0. Pass threshold for the unmask builtin
	// behavioral CAPTCHA (= 5-axis score on the challenge page). default 0.5.
	// Only consulted when Provider == "builtin"; the third-party providers
	// hand verification off to their own siteverify endpoint.
	BuiltinScoreThreshold float64 `yaml:"builtin_score_threshold,omitempty"`
	TurnstileSiteKey      string  `yaml:"turnstile_site_key,omitempty"`
	TurnstileSecretKey    string  `yaml:"turnstile_secret_key,omitempty"`
	HCaptchaSiteKey       string  `yaml:"hcaptcha_site_key,omitempty"`
	HCaptchaSecretKey     string  `yaml:"hcaptcha_secret_key,omitempty"`
	RecaptchaSiteKey      string  `yaml:"recaptcha_site_key,omitempty"`
	RecaptchaSecretKey    string  `yaml:"recaptcha_secret_key,omitempty"`
	RecaptchaMinScore     float64 `yaml:"recaptcha_min_score,omitempty"` // reCAPTCHA v3 score threshold. default 0.5
}

type Server struct {
	// Bind: an IP for TCP (= "127.0.0.1" / "0.0.0.0" / a specific IP).
	// For unix domain socket, "unix:/path/to.sock" form. When the "unix:"
	// prefix is detected, Port is ignored and listen happens on the socket
	// file (= no TCP listener). All major reverse proxies (nginx / Apache,
	// etc.) support unix-socket upstreams.
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
}

// DefaultListenSocket is the default unix-socket path for the HTTP listener in
// socket mode -- the value the settings UI pre-fills, so the field is never empty
// (an empty `bind: unix:` is a hard error, not silently defaulted).  Named for
// the HTTP role (not "admin", a holdover from the old unmask-admin binary) and
// parallel to the nginx-log socket /run/unmask/log.sock.
const DefaultListenSocket = "/run/unmask/http.sock"

// IPGeo: optional IP-geolocation mmdb integration (DB-IP Lite / MaxMind
// GeoLite2 / etc., all consumable via the maxminddb-format reader).
//
//	mmdb_path     : Country or City DB. Pointing at the City DB also enables
//	                city-level lookup. (e.g., /usr/share/GeoIP/GeoLite2-Country.mmdb).
//	                Unset → no country chart and no country row in popovers.
//	mmdb_asn_path : ASN DB (GeoLite2-ASN.mmdb etc.). Unset → no ASN row.
//	For GeoLite2 the MaxMind license prohibits bundling the binary, so the
//	user downloads it themselves; DB-IP Lite (CC BY 4.0) can be auto-fetched
//	via `unmask install-ipgeo`.
type IPGeo struct {
	MMDBPath    string `yaml:"mmdb_path"`
	MMDBASNPath string `yaml:"mmdb_asn_path"`
	// AutoFetch: when a managed (= default-path) DB-IP Lite mmdb is missing at
	// startup, fetch it in the background on first run so geo features light up
	// without a manual `unmask install-ipgeo` / 1-click -- regardless of how the
	// daemon was installed (binary / docker / any distro). Default true; set
	// false on air-gapped hosts to suppress the (non-fatal) fetch attempts.
	AutoFetch bool `yaml:"auto_fetch"`
}

// NginxLog: data source for the cookie-passage dashboard.
//
//	enabled    : false → do not render the access_log directive in
//	             nginx-rendered.{conf,server.inc}. Dashboard / hunt charts
//	             show all zeros, but UDP datagram send/receive cost is zero.
//	             Default true. Empty socket_path is effectively disabled too.
//	socket_path: path of the Unix datagram socket the admin binds. Keep in
//	             sync with nginx access_log syslog:server=unix:<same path>.
type NginxLog struct {
	Enabled    bool   `yaml:"enabled"`
	SocketPath string `yaml:"socket_path"`
}

// Nginx: input that `unmask render-nginx` uses to generate the nginx config.
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

	// ConfPath: host nginx.conf path, probed (read-only) before emitting our own
	// map_hash_bucket_size / map_hash_max_size into http.inc -- a duplicate of a
	// host-declared one makes `nginx -t` fail.  Empty → /etc/nginx/nginx.conf.
	// Bootstrap-only (install-time path), not web-editable.
	ConfPath string `yaml:"conf_path,omitempty"`

	// RateComposeMode selects the rate-limit ↔ challenge composition flow:
	//   "" / "auto" — probe the host nginx at startup: >=1.17.1 → compose,
	//                 otherwise classic.  Resolves to classic when nginx can't
	//                 be detected (admin-only box), so it is safe everywhere.
	//   "always"    — force compose (needs nginx 1.17.1+ for limit_req_dry_run;
	//                 `nginx -t` fails on older nginx).
	//   "never"     — force classic (deny zones can't preempt a challenge).
	// Compose lets a deny zone win over a protected-path challenge; classic's
	// REWRITE-phase gate pre-empts limit_req, so deny only hard-blocks
	// un-challenged traffic there.  See nginxconf.ComposeCapable.  Bootstrap-only
	// (an nginx-environment fact, not per-request policy).
	RateComposeMode string `yaml:"rate_compose_mode,omitempty"`

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
	// to enable.  Empty → no preset enabled (= no automatic crawler rescue).
	// Group definitions live in nginxconf/iprange.go.
	//
	// Schema matches BypassPathsConfig.EnabledPresets / ProtectedPathsConfig.
	// EnabledPresets so every preset list across the app reads the same way:
	// the user lists what's ON, never what's OFF.  Defaults() seeds this with
	// every shipped group ID so a fresh install still rescues crawlers out of
	// the box; toggling a group OFF in the UI removes its ID from this list.
	BypassIPEnabledPresets []string `yaml:"bypass_ip_enabled_presets,omitempty"`
	// IP / CIDR list excluded entirely from statistics (= own monitoring tools,
	// internal probes etc. that would otherwise be dashboard noise).  These IPs
	// skip the challenge AND are dropped from the unmask_minimal access_log, so
	// they never reach the funnel / cookie / crawler aggregation.
	StatsExcludeIPs []string `yaml:"stats_exclude_ips,omitempty"`
	// StatsExcludePrivateNetworks, when on, appends the private-network CIDRs
	// (RFC1918 + loopback + link-local, IPv4 and IPv6) to StatsExcludeIPs at
	// render time — a convenience preset for dropping internal monitoring / LAN
	// noise from the dashboard.  Off by default: an intranet deployment serves
	// real users from private addresses, and StatsExcludeIPs also bypasses the
	// challenge, so turning this on there would drop those users from stats AND
	// stop protecting them.  The operator opts in only on an internet-facing
	// site where private-source traffic is genuinely internal.
	StatsExcludePrivateNetworks bool `yaml:"stats_exclude_private_networks,omitempty"`
	// AdminAllowedIPs: source-IP allowlist for /admin/* (= the admin UI),
	// enforced at the admin handler layer (AdminIPAllowMiddleware).  Empty =
	// no IP restriction (login + CSRF + login rate-limit still apply).
	// Pairs with AdminAllowedHosts below: this is WHO may connect, that is
	// WHICH hostname exposes the UI.
	AdminAllowedIPs  []string `yaml:"admin_allowed_ips"`
	MetricsAllowFrom []string `yaml:"metrics_allow_from"`

	// AdminAllowedHosts: Host header allowlist for /admin/* (= the admin UI).
	// Empty = allow every Host that reaches the admin (= the default; an
	// install without a Host allowlist is exposed under any name nginx
	// proxies through).  When the same nginx serves multiple domains and
	// only one should expose the admin UI, list that domain here.
	// Comparison is case-insensitive and the port suffix (= :443 etc.) is
	// stripped before matching.
	//
	// Notes:
	//   - The challenge surfaces (= /unmask/challenge/, /unmask/_check,
	//     /unmask/_rl/, /unmask/healthz) ignore this list because they must
	//     work on every public-traffic vhost.  Only /admin/* is gated.
	//   - This is an HTTP-layer check inside admin; nginx still proxies
	//     /unmask/* to admin unchanged (= no nginx config involvement).
	AdminAllowedHosts []string `yaml:"admin_allowed_hosts,omitempty"`

	// TrustForwardedSite: in forward-auth mode the admin can derive the site
	// (= which vhost's policy applies) from an X-Unmask-Site header the proxy
	// sets, but nginx's default proxy_pass_request_headers forwards a
	// CLIENT-supplied value of the same name, and the admin cannot tell an
	// operator-set header from a client-forwarded one (both arrive from the
	// trusted loopback peer).  So it is NOT trusted by default: a client could
	// otherwise spoof X-Unmask-Site to select a weaker site's policy (=
	// observe_only bypass).  Default (false): the site is derived from the
	// proxy-forced X-Original-Host.  Set true ONLY when your proxy explicitly
	// OVERWRITES the header (= `proxy_set_header X-Unmask-Site $unmask_site;` so
	// a client value can't reach here).
	//
	// The forwarded JA4 (X-Client-JA4) has NO equivalent toggle: it is gated in
	// nginx by the rendered forward-auth-lbtrust.conf, which forwards the real
	// client JA4 only when the connection's original peer is inside a trusted LB
	// range (= TrustedLBPresets / TrustedLBExtra), and "" otherwise.  So a
	// non-LB peer's JA4 is dropped at the edge and never reaches the daemon --
	// trusted_lb_* is the single source of truth for both native and
	// forward-auth JA4 trust.
	TrustForwardedSite bool `yaml:"trust_forwarded_site,omitempty"`

	// Preset IDs of trusted LBs. Default is empty (= all disabled, secure default).
	// Pick IDs from the presets in nginxconf/lb_iprange.go to enable. Example:
	//   trusted_lb_presets: [gcp]
	// → trust X-Client-JA4 only on requests from the GCP LB IP range.
	TrustedLBPresets []string `yaml:"trusted_lb_presets,omitempty"`

	// Custom definitions for LBs not in the preset list. Merged in parallel
	// with presets into the effective list. Example:
	//   trusted_lb_extra:
	//     - id: "internal-lb"
	//       cidrs: ["10.0.1.0/24"]
	//       header: "$http_x_client_ja4"
	TrustedLBExtra []TrustedLBExtra `yaml:"trusted_lb_extra,omitempty"`

	SearchBots       SearchBotsConfig       `yaml:"search_bots"`
	JA4Verdicts      JA4VerdictsConfig      `yaml:"ja4_verdicts"`
	ChallengeTargets ChallengeTargetsConfig `yaml:"challenge_targets"`
	Honeypot         HoneypotConfig         `yaml:"honeypot"`
	Bans             BansConfig             `yaml:"bans,omitempty"`
	ProtectedPaths   ProtectedPathsConfig   `yaml:"protected_paths"`
	BypassPaths      BypassPathsConfig      `yaml:"bypass_paths"`
	Geo              GeoConfig              `yaml:"geo,omitempty"`

	// HTTPSRedirect, when on, emits an HTTP->HTTPS 301 at the very top of the
	// rendered server.inc — before any ban / honeypot / challenge gate.  A
	// plaintext request (no TLS, so no JA4) then leaves with a redirect instead
	// of being challenged and, if it trips a honeypot, banned on a JA4-less
	// row.  Behind an X-Forwarded-Proto-terminating LB the scheme is read from
	// that header (via the $unmask_forwarded_proto map, which falls back to
	// $scheme for a direct edge), so it is correct in both topologies.
	//
	// Off by default: turning it on means plaintext requests are no longer
	// inspected at all (no honeypot capture on :80), which is the operator's
	// call — some prefer to keep catching scanners on the plaintext port.
	HTTPSRedirect bool `yaml:"https_redirect,omitempty"`

	// HTTPSRedirectExempt lists requests that must NOT be 301'd even when
	// HTTPSRedirect is on — the redirect fires at the very top of server.inc,
	// so an un-exempted health check or ACME probe gets redirected before any
	// gate sees it.  A load-balancer health check that receives a 301 is a
	// failed check (the LB then drops the node from rotation and its traffic
	// silently stops), and GCP/AWS/k8s health probes reach the backend
	// directly without X-Forwarded-Proto, so $unmask_forwarded_proto falls back
	// to $scheme=http and the redirect fires on them.  ACME (path) and
	// load-balancer health checks (user-agent) ship as default-on presets;
	// custom rules add either axis.  Only consulted when HTTPSRedirect is on.
	HTTPSRedirectExempt HTTPSRedirectExemptConfig `yaml:"https_redirect_exempt,omitempty"`

	// AdvancedEnabled is the master reveal-gate for the standards-based
	// attestation axes below (Web Bot Auth + Privacy Pass).  They are
	// implemented and tested, but few clients/agents in the wild emit the
	// signatures/tokens yet (PAT is effectively Apple-only; Web Bot Auth is a
	// growing set of AI agents), so they stay hidden in the UI and inert until
	// an operator opts in.  Off by default.  When off, WebBotAuthActive /
	// PrivacyPassActive are false regardless of the per-feature Enabled flags,
	// so neither the nginx gates nor the auth_check veto-pass axes activate --
	// "off" means off, not just hidden.
	AdvancedEnabled bool              `yaml:"advanced_enabled,omitempty"`
	WebBotAuth      WebBotAuthConfig  `yaml:"web_bot_auth,omitempty"`
	PrivacyPass     PrivacyPassConfig `yaml:"privacy_pass,omitempty"`
}

// WebBotAuthActive reports whether Web Bot Auth signature verification should
// run: the advanced master switch AND the feature's own enable flag.  The
// nginx render + the auth_check veto-pass axis both gate on this, so flipping
// AdvancedEnabled off disables the feature everywhere without touching the
// per-feature config (which is preserved for when it is re-enabled).
func (n Nginx) WebBotAuthActive() bool { return n.AdvancedEnabled && n.WebBotAuth.Enabled }

// PrivacyPassActive reports whether Privacy Pass / PAT verification should run
// (advanced master switch AND the feature's own enable flag).  See
// WebBotAuthActive.
func (n Nginx) PrivacyPassActive() bool { return n.AdvancedEnabled && n.PrivacyPass.Enabled }

// WebBotAuthConfig: Web Bot Auth (= RFC 9421 HTTP Message Signatures
// applied to bot traffic, draft-meunier-web-bot-auth-architecture).
//
// When Enabled, the AuthCheck handler verifies any incoming Signature /
// Signature-Input / Signature-Agent header chain.  A valid signature with
// the "web-bot-auth" tag yields verdict=signed_agent + action=ok, so the
// request joins the search-bot rescue path instead of the challenge flow.
//
// AllowedOperators is an allowlist of agent URL hosts (e.g. "openai.com").
// An empty list is fail-closed -- no signed agent passes (see
// IsOperatorAllowed): a veto-pass that skips the whole challenge pipeline must
// not let every signed request through on an unconfigured install.  Operators
// opt in the agent hosts they trust (preset checkboxes or custom rows in the
// settings UI); operators outside the allowlist still get challenged.
//
// CacheTTLSec caps how long the in-memory directory cache holds a fetched
// JWK set per operator.  Default 3600s.
//
// AllowPrivateNetworks relaxes the directory-fetch SSRF dial guard so an
// operator whose key directory lives on a private / loopback address (= an
// intranet bot platform, or a test rig) can be fetched.  TLS verification,
// the https-only rule, and the redirect refusal stay in force.  Leave false
// unless every allowlisted operator is under your own control: with public
// operators this guard is what stops a forged Signature-Agent from steering
// the daemon's fetch at internal services.
type WebBotAuthConfig struct {
	Enabled              bool     `yaml:"enabled"`
	AllowedOperators     []string `yaml:"allowed_operators,omitempty"`
	CacheTTLSec          int      `yaml:"cache_ttl_sec,omitempty"`
	AllowPrivateNetworks bool     `yaml:"allow_private_networks,omitempty"`
}

// ResolvedCacheTTLSec returns CacheTTLSec or 3600 (= 1h) when unset.
func (w WebBotAuthConfig) ResolvedCacheTTLSec() int {
	if w.CacheTTLSec > 0 {
		return w.CacheTTLSec
	}
	return 3600
}

// IsOperatorAllowed checks the allowlist.  Empty list → no operator passes
// (fail closed): Web Bot Auth is a veto-pass that skips the whole challenge
// pipeline, so an unconfigured allowlist must not let every signed agent
// through.  Operators enable WBA by naming the agent hosts they trust.
func (w WebBotAuthConfig) IsOperatorAllowed(host string) bool {
	if len(w.AllowedOperators) == 0 {
		return false
	}
	for _, op := range w.AllowedOperators {
		if strings.EqualFold(op, host) {
			return true
		}
	}
	return false
}

// OperatorPreset is a well-known Web Bot Auth operator offered as a default-off
// checkbox in the settings UI.  Host is the Signature-Agent URL host matched in
// the allowlist; Label is the display name; Since is the unmask version the
// preset was added in (provenance, like the bypass-IP presets).
type OperatorPreset struct {
	Host  string
	Label string
	Since string
}

// WebBotAuthOperatorPresets are the well-known signed-agent operators surfaced
// as preset checkboxes on the Web Bot Auth tab.  Only operators that actually
// publish an http-message-signatures-directory belong here, so checking one
// reliably lets that operator through.  Checking a preset just adds its Host to
// AllowedOperators; AllowedOperators stays the single source of truth.
//
// Host is the Signature-Agent value (the directory host).  Every entry below
// was confirmed by fetching its /.well-known/http-message-signatures-directory
// (2026-06-24); operators not yet endpoint-confirmed are left out so a checkbox
// never silently fails to match.  Cloudflare curates the canonical registry at
// assets.radar.cloudflare.com/bots/signature-agent-registry.txt.
var WebBotAuthOperatorPresets = []OperatorPreset{
	{Host: "chatgpt.com", Label: "OpenAI ChatGPT", Since: "v0.1"},
	{Host: "shopify.com", Label: "Shopify", Since: "v0.1"},
	{Host: "www.browserbase.com", Label: "Browserbase", Since: "v0.1"},
	{Host: "you.com", Label: "You.com", Since: "v0.1"},
	{Host: "api.anchorbrowser.io", Label: "Anchor Browser", Since: "v0.1"},
	{Host: "api.manus.im", Label: "Manus", Since: "v0.1"},
	{Host: "www.klaviyo.com", Label: "Klaviyo", Since: "v0.1"},
}

// PrivacyPassConfig: Privacy Pass / Private Access Token acceptance (RFC 9577
// HTTP authentication scheme + RFC 9578 issuance).  When Enabled, the AuthCheck
// handler verifies an incoming "Authorization: PrivateToken" header against the
// configured trusted issuers; a valid, origin-bound token yields
// verdict=privacy_pass + action=pass, so an attested real client (e.g. an Apple
// device presenting a Private Access Token) skips the challenge.  Requests
// without a PrivateToken Authorization header are unaffected.
//
// Only the publicly verifiable token type 0x0002 (Blind RSA) is supported: the
// origin checks the issuer's RSASSA-PSS signature with the issuer's public key,
// no issuer secret involved.
//
// Issuers lists the trusted issuer keys.  An empty list means no token can match
// (fail closed): like Web Bot Auth, this is a veto-pass that skips the whole
// challenge pipeline, so trust is explicit -- the operator names the issuers
// (and their published token-keys) they accept.
type PrivacyPassConfig struct {
	Enabled bool `yaml:"enabled"`
	// EnabledIssuerPresets opts in well-known issuer presets by ID (see
	// PrivacyPassIssuerPresets); each contributes its issuer name + embedded
	// token-keys.  Issuers are operator-added custom issuers.
	EnabledIssuerPresets []string            `yaml:"enabled_issuer_presets,omitempty"`
	Issuers              []PrivacyPassIssuer `yaml:"issuers,omitempty"`
}

// PrivacyPassIssuer is one trusted issuer.  Name doubles as the TokenChallenge
// issuer_name (so it must match what the issuance handshake advertises) and the
// dashboard label; Key is the base64 DER SubjectPublicKeyInfo (id-RSASSA-PSS) of
// the issuer's published token-key.
type PrivacyPassIssuer struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

// PrivacyPassIssuerPreset is a well-known PAT issuer offered as a default-off
// checkbox.  Unlike Web Bot Auth operators, a PAT issuer's token-key ROTATES
// (Cloudflare ~daily, Fastly ~weekly) and the issuer publishes several at once,
// so a preset carries the issuer name + its directory URL (for the auto-refresh
// follow-up) + an embedded snapshot of the current keys.  ID is the stable value
// stored in EnabledIssuerPresets.
//
// NB: Apple is the ATTESTER, never the issuer -- Safari/iOS PATs are issued by
// Cloudflare / Fastly, so those are the issuers to trust.  Apple's own developer
// guidance points origins at the DEMO issuer directories (demo-pat.issuer.
// cloudflare.com / demo-issuer.private-access-tokens.fastly.com), so those are
// the recommended presets for guaranteed Safari/iOS interop.  The bare host
// pat-issuer.cloudflare.com sits behind Cloudflare Access (403 to every fetch,
// browser or not), but the real production directory IS publicly fetchable at
// the dap. subdomain on the RFC 9578 path -- offered as an extra opt-in preset
// below.  Whether Apple devices redeem against it as a named issuer is not
// Apple-documented, so it stays default-off and is labelled "production".
type PrivacyPassIssuerPreset struct {
	ID           string
	Label        string
	IssuerName   string
	DirectoryURL string
	Since        string
	SnapshotKeys []string // base64 DER SPKI (id-RSASSA-PSS); snapshot, keys rotate
}

// PrivacyPassIssuerPresets: the embedded snapshot.  Keys rotate, so the
// auto-refresh (re-fetch DirectoryURL) keeps them current; the snapshot is the
// offline fallback.
var PrivacyPassIssuerPresets = []PrivacyPassIssuerPreset{
	{
		ID: "cloudflare", Label: "Cloudflare (demo issuer)",
		IssuerName:   "demo-pat.issuer.cloudflare.com",
		DirectoryURL: "https://demo-pat.issuer.cloudflare.com/.well-known/private-token-issuer-directory",
		Since:        "v0.1",
		SnapshotKeys: []string{
			"MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAnxfH2GkcjixUfLEdbsEIUA3esFG344Z6CLBv7ewu9fqLbM5B-WANwly2qc7BihyirqIV6WDCx4W4EFZf8ExBml-O_J0IAybQCMDD8dpfUksUaSejBgQRDTYUNH4cp3pkSVcb29v73ifzhAin9XQ3Do--r4X_w3UA9-kxiJkhe4EKBBTxsOM0JtL0_y7BY9TaiR87GodVxtp8gKq6-MpA29k7WkhaUjbyrdHLZgjZJvRLLz6piFD2VU1wEx6xAx3r0vdhsE4I9-zIRW1xaHXckJrCL39FpmHTHFTutsIbeJ2dsODDVVnbK3ldw_j5vZtSwF304s-nl_wu6IGkiIN4nQIDAQAB",
			"MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA8IxteJV_QzGt6hC-mI-_8WKJ6hl20wGKKep2oVqQKY4DYXGhh8EP3wUA56qN14Y9XYBo9lqML96Lc44aoaQYbHpWKmmhDJ8m7nj2j0Ez8_DGldZYucn9E55o2bZ526XWpzVFqLvc1sykgkETdNvY1975MyPSIrEVnqDMWd0M-0wJo-n8pJHXAI3Ci7FaKRdJnyL8vKC22GayQa01J0Ax_jRJSP5nVVPMEOkAcJ7lOiJUwfFsuag4_34YIfehvBJiux5bt0JPPaQumBrhovbH45cfDss-xqQTztOBJ917r2ZcbRsnpZepOMq1tEv6dkQHtKfzBDXRzKJsL_9ShCGYIQIDAQAB",
		},
	},
	{
		ID: "fastly", Label: "Fastly (demo issuer)",
		IssuerName:   "demo-issuer.private-access-tokens.fastly.com",
		DirectoryURL: "https://demo-issuer.private-access-tokens.fastly.com/.well-known/token-issuer-directory",
		Since:        "v0.1",
		SnapshotKeys: []string{
			"MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEApas5ORbANn4ljy4ehZfQVtnb1H_AaOpK5BxQIx1aS3w-8s7luSUPXfqqRwSqyYPFuRB0upGhN3lIEwh-8K_qlQmgscuZQpJEmg8_yMAQ0_mOZqc0LJnpb0IO-AMWefgmgXsJH5lDIUQUCpZkJm5LkGGxubQQWDRkZdgecljCuPFFGPONB7vzQJOK11tn4AuE7xOaW6A7Pm1sGoZNK181L-rDlH5NAX_E1J1C4O5a25tGAvuK73dxN_yBkP4bKJYs1G5CaZpSiHfFmm9QAjW-UNhcZ7c4GLJSxntarZHRqD6fgA3TTUBf0yuAyCtNI7AHHWjxNqqdCnghsF_TKCIRhQIDAQAB",
			"MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAwjw0cXAwtwbaB0aM95IRVs3RicxQscL3k0iP-Ku7qJJKb9U4dQOIfdSDj3UsYVVv5_bTJ6N9TOaUB4Dilhbsb6uE_FoBR281gXHguPm4l-R1qKKTZq9bcdbKODU7BiAkPNsQ1x7y-8u9JQvDT0-Z5edIrTmIuG1oG7QDrm6WAV-0dXefQZ16rCLc4Hm2qOTvSmkFRdT5IkBCb39hklDcRnG3UKzWa0_VhJHGxZP88q9iBqxRsSN365s72G7i8dYECUl49kv6VtPJTXVriHcHwNA23PazMoxu2nJZerQMTlUlWm0kGOQDZqpxeJ2StVtP8i8klKr8aRq8RayXZgMRVQIDAQAB",
		},
	},
	{
		// Cloudflare's real production issuer.  The bare host
		// pat-issuer.cloudflare.com is behind Cloudflare Access (403), but the
		// directory origins actually fetch lives at the dap. subdomain on the RFC
		// 9578 path and is publicly fetchable.  Keys rotate ~daily (current +
		// previous, published 20:00 UTC), so the live re-fetch is what keeps this
		// usable -- the embedded snapshot is a best-effort offline fallback that
		// goes stale within a day.  Default-off: Apple documents only the demo
		// issuer for origin interop, so prefer "cloudflare" unless you
		// specifically want to verify against Cloudflare's production keys.
		ID: "cloudflare-prod", Label: "Cloudflare (production issuer)",
		IssuerName:   "dap.pat-issuer.cloudflare.com",
		DirectoryURL: "https://dap.pat-issuer.cloudflare.com/.well-known/private-token-issuer-directory",
		Since:        "v0.1",
		SnapshotKeys: []string{
			"MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAtRBq2jki6stE40DLtVAF9UX1uHPzfiGpwIiLveQMKXPXpCAaSJng2mKlS9rKEERfoc47T5cSBPisAEg9RaSKfWPExnDxCojDFoSzYFEaRNdM7urfAxmb6Q_pmh-C5CwGOf8RAGC1d7ebdq44pRELP3F9W8b8RBmzqBb9npXYTu558riKJjfv7CKJ2EjCoNEVYoBXkjNiPF9SJQnu8N4JhEsNfNC5ggD-RZPj3hmVrxndgAqWFC4keup06lTERWc8QXA2mSDG-zBimnU155oll-gwacgvPbmlhhjx-RHNfplmcVBA0i4l4Qvtgkmxxn3exWzIKhh5XtK_RwbVgL3wTQIDAQAB",
			"MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAm9eIxS3nZkId7kfQEy1pepKVpYz-iLMxSheJOD0x5n7JbV_ATa3tbR2NuzO7Rm1fQwbqMIxUBivF_rJVyw0zGmwBRUYEzYexxVXPQdkNqyx5IEm2Gd_v0Rhgmx1yNuJ58p7OHPmCn2iUkBaxzIJ6YozyLnfRNZvfNosuvqAr_df2Urm4C1qX5RKS7ut0YxDKgQM79z1Ib7_34MmErZE7-3QQsjCyfmlgCKbW1LAQj1pIu9uXoSGrNb_gxfF5ploNEVpVoUYStGD77VZFKsw54o8gAXiOgNuNZiXonGx9Q8XKraOhqV917joOP5zpVxCMMXTmu9z-D0cHGqlBRgZh8QIDAQAB",
		},
	},
}

// IssuerConfigs maps the enabled presets (each as one config carrying its
// directory URL + snapshot keys -- the verifier fetches the live keys and falls
// back to the snapshot) + the custom issuers into the verifier's settings-free
// IssuerConfig shape.
func (c PrivacyPassConfig) IssuerConfigs() []privacypass.IssuerConfig {
	out := make([]privacypass.IssuerConfig, 0, len(c.Issuers)+len(c.EnabledIssuerPresets))
	enabled := map[string]bool{}
	for _, id := range c.EnabledIssuerPresets {
		enabled[id] = true
	}
	for _, p := range PrivacyPassIssuerPresets {
		if !enabled[p.ID] {
			continue
		}
		out = append(out, privacypass.IssuerConfig{
			Name:         p.IssuerName,
			DirectoryURL: p.DirectoryURL,
			SnapshotKeys: p.SnapshotKeys,
		})
	}
	for _, is := range c.Issuers {
		out = append(out, privacypass.IssuerConfig{Name: is.Name, SPKIB64: is.Key})
	}
	return out
}

// BansConfig: per-source default action for entries on the ban list.  The
// "honeypot" source defers to HoneypotConfig.DefaultAction (= keeps the
// existing knob untouched).  Other sources (= "manual" / "community_bans")
// consult this struct.  Values follow the rate-limit chain modes:
// deny / pow_only / pow_then_captcha / captcha_only.  Empty fields fall
// back to "captcha_only" -- false positives on a manual entry or a
// foreign-feed import recover when the visitor is actually human; the
// operator can pick "deny" per row when certainty is high.
type BansConfig struct {
	ManualDefaultAction        string `yaml:"manual_default_action,omitempty"`
	CommunityBansDefaultAction string `yaml:"community_bans_default_action,omitempty"`
	// Deny-page design (theme / copy preset / colors) moved to BrandingValues
	// (DenyBan*) so it follows the per-site appearance record like the logo.
}

// ResolveAction returns the effective action for a given ban source.
// "honeypot" defers to honeypotDefault (= HoneypotConfig.DefaultAction)
// so the operator's pick on the honeypot tab keeps working.
// manual / community_bans fall back to "captcha_only" so a human still
// recovers from a mis-identified ban; unknown sources hard-deny.
func (b BansConfig) ResolveAction(source, honeypotDefault string) string {
	resolve := func(v, fallback string) string {
		v = strings.TrimSpace(v)
		if v == "" {
			return fallback
		}
		return v
	}
	switch source {
	case "honeypot":
		return resolve(honeypotDefault, RateChallengePoWThenCaptcha)
	case "manual":
		return resolve(b.ManualDefaultAction, RateChallengeCaptchaOnly)
	case "community_bans":
		return resolve(b.CommunityBansDefaultAction, RateChallengeCaptchaOnly)
	}
	return RateChallengeDeny
}

// GeoConfig: country-based decision axis, applied in both forward-auth mode
// (= admin /authcheck does the lookup live) and native nginx-plugin mode
// (= render-time mmdb walk emits a `geo $remote_addr $unmask_country` block
// into http.inc).  Either way the plugin / module itself does not link
// libmaxminddb — admin is the only consumer of the mmdb file.
//
// Requires IPGeo.MMDBPath to be configured (= mmdb loaded at startup for
// forward-auth mode, walked at render time for native mode).  Rule / mmdb
// changes take effect after `unmask render-nginx && nginx -s reload`
// in native mode; forward-auth mode reloads the mmdb on settings save.
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
	GeoActionSkip           = "skip"
	GeoActionPoWOnly        = RateChallengePoWOnly
	GeoActionCaptchaOnly    = RateChallengeCaptchaOnly
	GeoActionPoWThenCaptcha = RateChallengePoWThenCaptcha
	GeoActionDeny           = RateChallengeDeny
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
// v2 layout (= multi-site phase 2): Paths is a flat struct slice; each row
// carries an optional `site` filter -- empty applies to all sites, a string
// applies only when the visitor's `$host` equals that value.  Replaces the
// pre-v2 parallel-array form (Extra / ExtraTitle / ExtraDisabled /
// ExtraUpdatedAt / ExtraSite).
type BypassPathsConfig struct {
	// EnabledPresets / DisabledPresets record the operator's DEVIATIONS from
	// each preset's factory default (= nginxconf BypassPathGroup.DefaultOn):
	//
	//   - EnabledPresets:  default-OFF presets the operator turned ON
	//   - DisabledPresets: default-ON presets the operator turned OFF
	//
	// A preset in neither list follows its code-declared default, so a preset
	// added in a later version brings its own default to existing installs
	// (behind the SeenVersion NEW gate) without any config migration.
	// Resolution lives in nginxconf.EffectiveBypassPathPresets; the settings
	// save writes only deviations (a choice that matches the default is stored
	// as nothing).  Unknown IDs on either list are ignored.
	EnabledPresets  []string `yaml:"enabled_presets,omitempty"`
	DisabledPresets []string `yaml:"disabled_presets,omitempty"`
	// Paths: per-row custom bypass entries.  Order is preserved (= operator-
	// edited).  See BypassPath for the per-row fields.
	Paths []BypassPath `yaml:"paths,omitempty"`
}

// BypassPath: one custom bypass row.  Site is the v2 multi-site filter:
// empty = applies to all sites, a host string = applies only when the
// request's normalized site equals that value.
type BypassPath struct {
	Path      string `yaml:"path"`
	Title     string `yaml:"title,omitempty"`
	Disabled  bool   `yaml:"disabled,omitempty"`
	UpdatedAt int64  `yaml:"updated_at,omitempty"`
	Site      string `yaml:"site,omitempty"`
}

// ResolvePaths returns the BypassPath rows whose Site matches the requested
// site identifier.  Empty Site matches every site (= the "all sites" rule);
// otherwise only the exact match is returned.  Order is preserved.
func (b BypassPathsConfig) ResolvePaths(site string) []BypassPath {
	out := make([]BypassPath, 0, len(b.Paths))
	for _, p := range b.Paths {
		if p.Site == "" || p.Site == site {
			out = append(out, p)
		}
	}
	return out
}

// HTTPSRedirectExemptConfig: which requests skip the HTTP->HTTPS 301.  Same
// deviation model as BypassPathsConfig — EnabledPresets/DisabledPresets record
// only departures from each preset's factory default (nginxconf
// RedirectExemptGroup.DefaultOn), and Rules holds custom per-row exemptions.
// Unlike bypass presets there is no SeenVersion gate: a missing exemption is
// the dangerous state (a 301'd health check drops the node), so a default-on
// exemption applies immediately on upgrade.
type HTTPSRedirectExemptConfig struct {
	EnabledPresets  []string                  `yaml:"enabled_presets,omitempty"`
	DisabledPresets []string                  `yaml:"disabled_presets,omitempty"`
	Rules           []HTTPSRedirectExemptRule `yaml:"rules,omitempty"`
}

// HTTPSRedirectExemptRule: one custom exemption row.  Type selects the match
// axis: "path" tests $request_uri (like a bypass path), "ua" tests
// $http_user_agent case-insensitively (for load-balancer / monitor probes that
// vary the path but keep a stable user-agent).  Pattern is a PCRE regex.
type HTTPSRedirectExemptRule struct {
	Type      string `yaml:"type"` // "path" | "ua"
	Pattern   string `yaml:"pattern"`
	Title     string `yaml:"title,omitempty"`
	Disabled  bool   `yaml:"disabled,omitempty"`
	UpdatedAt int64  `yaml:"updated_at,omitempty"`
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
// gate / important-path protection).  v2 stores rows as a flat struct slice
// with a per-row Site filter; Mode / chMode override stay on the row.
type ProtectedPathsConfig struct {
	// EnabledPresets: explicit opt-in list of preset group IDs to enable.
	// Absent / nil / [] all mean "no preset enabled".  Protected-paths
	// presets (= unmask / common-admin etc.) are off by default because
	// turning them on inserts a CAPTCHA before admin login -- always a
	// deliberate operator choice, never a default.
	EnabledPresets []string `yaml:"enabled_presets,omitempty"`
	// Paths: per-row custom protected entries.  See ProtectedPath for the
	// per-row fields.
	Paths []ProtectedPath `yaml:"paths,omitempty"`
	// DefaultAction: chain to run when a request hits a protected path and
	// challenge fires (= chMode used by challenge.html JS).  Empty =
	// inherit ChallengeTargets.DefaultAction → RateLimit.Default.
	DefaultAction string `yaml:"default_action,omitempty"`
	// PresetAction: per-preset chMode override (preset ID → chain).  Stored
	// now; path-based dispatch wiring is a follow-up.
	PresetAction map[string]string `yaml:"preset_action,omitempty"`
}

// ProtectedPath: one custom protected-path row.  Mode is the rule's match
// mode ("captcha" / "pow" / "strict").  Action is the chain override (= same
// chMode strings as RateChallenge*); empty -> inherit DefaultAction.
type ProtectedPath struct {
	Path      string `yaml:"path"`
	Title     string `yaml:"title,omitempty"`
	Mode      string `yaml:"mode,omitempty"`
	Action    string `yaml:"action,omitempty"`
	Disabled  bool   `yaml:"disabled,omitempty"`
	UpdatedAt int64  `yaml:"updated_at,omitempty"`
	Site      string `yaml:"site,omitempty"`
}

// ResolvePaths returns ProtectedPath rows whose Site matches `site`.
// Same semantics as BypassPathsConfig.ResolvePaths.
func (p ProtectedPathsConfig) ResolvePaths(site string) []ProtectedPath {
	out := make([]ProtectedPath, 0, len(p.Paths))
	for _, r := range p.Paths {
		if r.Site == "" || r.Site == site {
			out = append(out, r)
		}
	}
	return out
}

// HoneypotConfig: honeypot path configuration + persistent BAN list management.
//
// Behavior:
//  1. nginx matches a honeypot path (= /wp-login.php etc.) → $serve_bot_challenge=1
//  2. nginx access_log writes "hp=1 ja4=t13d... ip=1.2.3.4" → the admin
//     receives it on the syslog socket
//  3. admin appends the (ip, ja4) tuple to `ban_file_path` (= TTL=ban_duration)
//  4. nginx module watches ban_file by mtime and exposes $unmask_banned=1
//  5. user picks the behavior in their server block:
//     `if ($unmask_banned = 1) { rewrite ^ /unmask/challenge/ last; }`
//     (= force CAPTCHA) or `return 403;` (= hard ban). The behavior is the
//     conf's responsibility (= unmask only exposes the variable)
//
// v2 layout: list-style URLs are stored as []HoneypotURL with a per-row site
// filter.  Per-site scalar parameters (= BanDurationSec etc.) live in
// Default + Sites map, mirroring Branding / Challenge.  Install-wide knobs
// (= BanFilePath / DefaultAction / PresetAction) stay on the parent struct.
type HoneypotConfig struct {
	// DisabledPresets: preset groups that are kept OFF (= same shape as
	// search-bots etc.).  Only meaningful for groups whose HoneypotGroup.OptIn
	// is false (= the historical on-by-default set: wordpress / secrets /
	// cms-admin / shell / cgi-tomcat / scan-paths).
	DisabledPresets []string `yaml:"disabled_presets,omitempty"`
	// EnabledPresets: explicit opt-in list for preset groups whose
	// HoneypotGroup.OptIn is true (= patterns that need a human go-ahead
	// because the trade-off is non-obvious -- e.g. sql-injection probes that
	// could collide with a site-search query echoing SQL keywords).  Listed
	// here = the group renders; absent = the group stays inactive even
	// though the patterns ship in the binary.
	EnabledPresets []string `yaml:"enabled_presets,omitempty"`
	// URLs: custom honeypot path rows.  Each row may bind to a single site
	// via the Site field; an empty Site applies to every host.  Honeypot
	// fires BAN on hit with fixed behavior, so there is no per-row mode
	// column.  For "force CAPTCHA / PoW" use the separate protected-paths
	// tab.
	URLs []HoneypotURL `yaml:"urls,omitempty"`
	// BanFilePath: output path for the ban list (= honeypot / manual / all
	// sources).  Install-wide; default /var/lib/unmask/nginx/banned.txt
	// because the file is admin-rendered state, not a user-edited config
	// (= FHS: /etc/ is for hand-edited files only).  Only the native mode
	// reads this -- forward-auth checks the DB directly.
	BanFilePath string `yaml:"ban_file_path,omitempty"`
	// DefaultAction: chain to run when a honeypot trip results in a
	// challenge (= chMode used by challenge.html JS).  Empty = inherit
	// ChallengeTargets.DefaultAction → RateLimit.Default.
	DefaultAction string `yaml:"default_action,omitempty"`
	// PresetAction: per-preset action override (preset ID → mode).
	// Path-level resolution (= which preset was tripped) is wired up in a
	// follow-up; the field is stored now so the UI is round-trippable.
	PresetAction map[string]string `yaml:"preset_action,omitempty"`
	// BanDurationSec: ban TTL in seconds applied to every honeypot trip.
	// 0 falls back to the 24h default (= ResolvedBanDurationSec).  Single
	// global value; per-site overrides were considered and dropped because
	// the ban list is keyed on IP+JA4 and not on the visited host.
	BanDurationSec int `yaml:"ban_duration_sec,omitempty"`
}

// HoneypotURL: one custom honeypot path row.  No Mode column (= honeypot
// behavior is uniform).  Action overrides the chain when present.
type HoneypotURL struct {
	Path      string `yaml:"path"`
	Title     string `yaml:"title,omitempty"`
	Action    string `yaml:"action,omitempty"`
	Disabled  bool   `yaml:"disabled,omitempty"`
	UpdatedAt int64  `yaml:"updated_at,omitempty"`
	Site      string `yaml:"site,omitempty"`
}

// ResolveURLs: filter URLs by site (same shape as BypassPathsConfig.ResolvePaths).
func (h HoneypotConfig) ResolveURLs(site string) []HoneypotURL {
	out := make([]HoneypotURL, 0, len(h.URLs))
	for _, u := range h.URLs {
		if u.Site == "" || u.Site == site {
			out = append(out, u)
		}
	}
	return out
}

// ResolvedBanDurationSec returns BanDurationSec when set; otherwise the
// canonical 24h default so an empty value does not flip the ban to
// "permanent" by accident.
func (h HoneypotConfig) ResolvedBanDurationSec() int {
	if h.BanDurationSec > 0 {
		return h.BanDurationSec
	}
	return 86400
}

// ChallengeTargetsConfig: which UAs receive a challenge when bot signals fire.
//
//	all              : true → always target regardless of UA (= preset / extra ignored)
//	disabled_presets : list of preset-group IDs to keep OFF
//	extra            : custom UA patterns (= nginx case-insensitive regex)
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
	// DisabledPresets was removed with the built-in whitelist presets
	// (Googlebot / Bingbot / ...).  Search/AI rescue now flows through the
	// upstream crawler-user-agents.json path (UpstreamGroupMode) plus Extra;
	// any leftover `disabled_presets:` key in an old config.yml is ignored.
	Extra          []string `yaml:"extra"`
	ExtraTitle     []string `yaml:"extra_title,omitempty"`
	ExtraDisabled  []bool   `yaml:"extra_disabled,omitempty"`
	ExtraUpdatedAt []int64  `yaml:"extra_updated_at,omitempty"` // unix sec. analogous to preset's AddedIn
	// UpstreamDisabled: per-pattern disable list applied to the upstream
	// crawler-user-agents.json auto-rescue.  Patterns listed here will not
	// be auto-passed via the search_ai branch, even if they match a
	// search-engine / ai-crawler / advertising tag.  Edited via the
	// "details" modal on the settings UI.
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
//
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
//     (= lowercase letters + digits + _). Must not collide with preset IDs.
//   - cidrs  : trusted source IP ranges. IPv4 / IPv6 may be mixed.
//   - header : nginx variable this LB places JA4 into (= "$http_x_client_ja4"
//     etc.). Default is "$http_x_client_ja4".
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

// GlobalConfig: settings-wide knobs that cross axis boundaries (= UA /
// JA4 / honeypot / protected paths).  Lives at the root of settings so the
// "Operating mode" tab can drive them without dragging other tabs into shared
// state.
// OverBlockConfig: the over-block circuit breaker.  The daemon samples the
// challenge funnel; when the same visitors are being re-challenged instead of
// passing (a high serves-per-IP ratio over the window = a challenge loop, the
// shape of the 2026-06-08 tool1-jp incident that ran ~14h before anyone
// noticed), it raises an alert and -- when AutoPassthrough is set -- temporarily
// lets visitors through until the signal clears, capping the blast radius of any
// challenge regression.
//
// It's a safety net, so it runs by default (alert-only) with no settings UI; the
// operator tunes or turns it off via config only.
type OverBlockConfig struct {
	// Disabled turns the breaker OFF.  Zero value = false = the breaker runs out
	// of the box (on unless the operator explicitly opts out).
	Disabled bool `yaml:"disabled,omitempty"`
	// WindowMinutes: the sampling window for the serves-per-IP ratio. Default 10.
	WindowMinutes int `yaml:"window_minutes,omitempty"`
	// MinServes: don't evaluate the ratio below this serve volume in the window
	// (= avoids tripping on a handful of requests). Default 50.
	MinServes int `yaml:"min_serves,omitempty"`
	// MaxServesPerIP: serves/distinct-IP at or above this trips the breaker
	// (= the same IPs being re-challenged rather than passing). Default 4.
	MaxServesPerIP int `yaml:"max_serves_per_ip,omitempty"`
	// AutoPassthrough: while tripped, also flip serveBotChallenge to passthrough
	// (= issue a signed _bv, let visitors through).  Default false = alert only;
	// the operator decides whether to drop protection automatically.
	AutoPassthrough bool `yaml:"auto_passthrough,omitempty"`
}

// WindowMinutesResolved returns the sampling window, defaulting to 10.
func (c OverBlockConfig) WindowMinutesResolved() int {
	if c.WindowMinutes <= 0 {
		return 10
	}
	return c.WindowMinutes
}

// MinServesResolved returns the minimum serve volume to evaluate, defaulting to 50.
func (c OverBlockConfig) MinServesResolved() int {
	if c.MinServes <= 0 {
		return 50
	}
	return c.MinServes
}

// MaxServesPerIPResolved returns the serves/IP trip threshold, defaulting to 4.
func (c OverBlockConfig) MaxServesPerIPResolved() int {
	if c.MaxServesPerIP <= 0 {
		return 4
	}
	return c.MaxServesPerIP
}

// RebindConfig: the roaming silent-rebind policy.  When a client's _bv no
// longer verifies because its IP changed (a 5G cell handoff to a new CGNAT
// address), the admin can re-bind a fresh _bv entry for the new IP on the
// challenge route instead of issuing a PoW -- if the request carries a valid
// _bvj proving an earlier solve AND still matches that solve's fingerprint.
// This cuts re-challenges for mobile clients toward one per device rather than
// one per cell.  Gated by three independent checks (see the _bvj doc in package
// cookies):
//   - signature + JA4/UA fingerprint match (the same client that solved)
//   - ASN veto (the new IP shares the solve-time autonomous system) when an ASN
//     db is loaded; skipped otherwise so the feature still works without one
//   - a server-side per-lineage cap (lifetime count + hourly rate), which is
//     the only bound left when no ASN db is present
//
// On by default; the operator opts out or tunes via config (no settings UI).
type RebindConfig struct {
	// Disabled turns silent rebind OFF.  Zero value = false = rebind runs out of
	// the box (on unless the operator explicitly opts out).
	Disabled bool `yaml:"disabled,omitempty"`
	// AllowNoJA4 permits rebind even when no JA4 is available (a pure forward-auth
	// deployment that doesn't forward X-Client-JA4): the JA4 match degenerates to
	// empty==empty, leaving rebind to lean on the ASN veto + cap alone.  Default
	// false = refuse rebind without a JA4 (safe side).
	AllowNoJA4 bool `yaml:"allow_no_ja4,omitempty"`
	// ASNVeto selects the ASN check: "auto" (default) applies it when an ASN db
	// is loaded and skips it otherwise; "off" never applies it (cap-only, e.g.
	// to avoid splitting a CGNAT carrier that spans multiple AS numbers).
	ASNVeto string `yaml:"asn_veto,omitempty"`
	// MaxRebinds caps how many times one solve (one lineage) is ever re-bound.
	// Default 16.
	MaxRebinds int `yaml:"max_rebinds,omitempty"`
	// MaxRebindsPerHour caps re-binds per lineage within a rolling hour (a phone
	// roaming naturally re-binds a few times; a stolen cookie fanned out across a
	// proxy pool would burst).  Default 4.
	MaxRebindsPerHour int `yaml:"max_rebinds_per_hour,omitempty"`
	// MaxEntries caps how many per-IP signatures one _bv accumulates -- the number
	// of networks a roaming client (home wifi/5G, office, cafes, ...) stays
	// verified on at once before the oldest is dropped.  Clamped to [1, 16]; 16 is
	// the verifier ceiling (Go cookies.maxVerifyEntries and the native plugin's
	// matching loop).  Default 16.  Independent of rebind: it bounds the _bv list
	// even when silent rebind is off.
	MaxEntries int `yaml:"max_entries,omitempty"`
}

// RebindEnabled reports whether silent rebind is active.
func (c RebindConfig) RebindEnabled() bool { return !c.Disabled }

// bvMaxEntriesCeiling mirrors cookies.maxVerifyEntries (kept as a literal to
// avoid a settings->cookies import); AppendEntry re-clamps to the same value.
const bvMaxEntriesCeiling = 16

// MaxEntriesResolved returns the roaming network cap (how many per-IP _bv
// signatures accumulate), defaulting to the ceiling and clamped to [1, 16].
func (c RebindConfig) MaxEntriesResolved() int {
	if c.MaxEntries <= 0 {
		return bvMaxEntriesCeiling
	}
	if c.MaxEntries > bvMaxEntriesCeiling {
		return bvMaxEntriesCeiling
	}
	return c.MaxEntries
}

// RebindMode collapses Disabled + ASNVeto into one operator-facing mode:
//
//	"strict" = silent rebind off; only the accumulated per-IP _bv list works, so
//	           every genuinely new IP re-challenges (most conservative).
//	"asn"    = rebind on, ASN-gated: a new IP is rebound silently only when it
//	           shares the solve-time autonomous system (same carrier).  Default.
//	"any"    = rebind on, no ASN gate: any new IP with the same JA4/UA/lineage is
//	           rebound (still cap- and budget-bounded).  Loosest.
func (c RebindConfig) RebindMode() string {
	if c.Disabled {
		return "strict"
	}
	if c.ASNVetoResolved() == "off" {
		return "any"
	}
	return "asn"
}

// SetRebindMode applies a RebindMode() value back onto Disabled + ASNVeto.
// Unknown values fall back to the safe default ("asn").
func (c *RebindConfig) SetRebindMode(mode string) {
	switch mode {
	case "strict":
		c.Disabled = true
		c.ASNVeto = ""
	case "any":
		c.Disabled = false
		c.ASNVeto = "off"
	default: // "asn"
		c.Disabled = false
		c.ASNVeto = "auto"
	}
}

// ASNVetoResolved returns the normalized ASN-veto mode ("auto" | "off").
func (c RebindConfig) ASNVetoResolved() string {
	if c.ASNVeto == "off" {
		return "off"
	}
	return "auto"
}

// MaxRebindsResolved returns the lifetime rebind cap, defaulting to 16.
func (c RebindConfig) MaxRebindsResolved() int {
	if c.MaxRebinds <= 0 {
		return 16
	}
	return c.MaxRebinds
}

// MaxRebindsPerHourResolved returns the hourly rebind cap, defaulting to 4.
func (c RebindConfig) MaxRebindsPerHourResolved() int {
	if c.MaxRebindsPerHour <= 0 {
		return 4
	}
	return c.MaxRebindsPerHour
}

type GlobalConfig struct {
	// Passthrough = monitoring mode.  When true, the admin's serveBotChallenge
	// short-circuits and bounces the user straight back to the original URL
	// without issuing PoW / CAPTCHA.  Useful for staged rollouts: signals
	// are still recorded in events / dashboard, but visitors are never
	// inconvenienced.
	Passthrough bool `yaml:"passthrough,omitempty"`
	// KnownBrowserAction: chain for no-match requests whose UA looks like a
	// real browser (= classify.IsKnownBrowser).  Default "pow_only" = a
	// transparent first-visit PoW (defense in depth behind the JA4 axis).  Set
	// "pass" for zero-friction pass-through of JA4-confirmed real browsers, or
	// pow_then_captcha / captcha_only / deny to gate harder.
	KnownBrowserAction string `yaml:"known_browser_action,omitempty"`
	// UnknownUAAction: chain for no-match requests whose UA is NOT a known
	// browser (= curl / library / empty / oddball).  Default (unset) ==
	// pow_only: defaults() deliberately leaves this empty and uaDecide maps
	// empty -> RateChallengePoWOnly, so non-browser clients are PoW-challenged
	// out of the box (a JS PoW that scripts can't solve).  Set "pass" to let
	// them through, or captcha_only / deny to gate harder.
	UnknownUAAction string `yaml:"unknown_ua_action,omitempty"`
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

// HostInventoryConfig governs the host inventory (= multi-host).  A host id is
// the unmask instance's own config, not a client-supplied header, so there is
// no acceptance mode — only a Disabled list of retired / mis-configured
// instances.  Disabled hosts are hidden from the host picker and excluded
// from dashboard aggregation (their events stay in the DB).
type HostInventoryConfig struct {
	Disabled []string `yaml:"disabled,omitempty"`
}

// IsDisabled reports whether host is in the disabled list.
func (c HostInventoryConfig) IsDisabled(host string) bool {
	for _, d := range c.Disabled {
		if d == host {
			return true
		}
	}
	return false
}

type Settings struct {
	DB            DB                   `yaml:"db"`
	Secret        Secret               `yaml:"secret"`
	Challenge     ChallengeConfig      `yaml:"challenge"`
	Branding      Branding             `yaml:"branding,omitempty"`
	Server        Server               `yaml:"server"`
	IPGeo         IPGeo                `yaml:"ipgeo"`
	NginxLog      NginxLog             `yaml:"nginx_log"`
	Nginx         Nginx                `yaml:"nginx"`
	RateLimit     RateLimitConfig      `yaml:"rate_limit"`
	CommunityBans CommunityBans        `yaml:"community_bans,omitempty"`
	Notifications Notifications        `yaml:"notifications,omitempty"`
	SMTP          SMTP                 `yaml:"smtp,omitempty"`
	Global        GlobalConfig         `yaml:"global,omitempty"`
	OverBlock     OverBlockConfig      `yaml:"over_block_breaker,omitempty"`
	Rebind        RebindConfig         `yaml:"rebind,omitempty"`
	Sites         SiteAcceptanceConfig `yaml:"sites,omitempty"`
	Hosts         HostInventoryConfig  `yaml:"hosts,omitempty"`
	// VersionCheckURL: where the admin overview checks for the latest unmask
	// release + changelog.  Empty -> the default (unmask.sh).  Advanced override;
	// the on/off switch is VersionCheckDisabled (toggled from the About tab).
	VersionCheckURL string `yaml:"version_check_url,omitempty"`
	// VersionCheckDisabled: opt out of the update check entirely (no outbound
	// call at all).  Default false = the check runs.  Toggled from the About tab.
	VersionCheckDisabled bool `yaml:"version_check_disabled,omitempty"`
	// EventsRetentionDays: retention days for raw unmask_event rows. Default 30
	// (hunt is 24h, dashboard keeps its own aggregate up to 30d, so raw events
	// past 30d only serve --ref lookups / audit).
	// 0 = retain forever (= prune disabled). Aggregates (= unmask_aggregate)
	// are not affected and persist forever. On admin server startup, a
	// goroutine runs `DELETE FROM unmask_event WHERE date_created < now - N days`
	// idempotently every 24h.  No omitempty: 0 is the zero value, so omitempty
	// would drop it on Save and Load would re-default it to 90 -- silently
	// deleting the history the operator chose to keep forever.
	EventsRetentionDays int `yaml:"events_retention_days"`
	// AuditRetentionDays: retention days for the admin-action log
	// (unmask_user_audit: login / settings save / user + ban mutations).
	// Default 90. 0 = retain forever. Pruned by the same 24h startup goroutine
	// as events (`DELETE FROM unmask_user_audit WHERE at < now - N days`).
	// No omitempty (same 0-must-round-trip reason as EventsRetentionDays).
	AuditRetentionDays int `yaml:"audit_retention_days"`
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

// CommunityBans: shared BAN feed (= submit / subscribe mechanism for the
// unmask.sh central hub).
//
// Overview:
//   - When submit_enabled is true, the BAN button on the hunt page, with
//     "share" checked, POSTs ip / ja4 / reason / comment to unmask.sh.
//   - When subscribe_mode is fetch / fetch_apply, feed_url is pulled hourly
//     and /etc/unmask/community-bans-*.map (= 3 files) is regenerated. It
//     feeds into `$community_bans_hit` in nginx-rendered.conf; on hit the
//     response is fixed to CAPTCHA (= cannot block).
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
type CommunityBans struct {
	SubmitEnabled bool `yaml:"submit_enabled"`
	// SubscribeMode: "off" (= no pull, maps cleared), "fetch" (= pull for the
	// browse list only, no enforcement, no auto-apply), "fetch_apply" (= pull
	// + write nginx maps + auto-apply).  "" treated as off.
	SubscribeMode string `yaml:"subscribe_mode,omitempty"`
	Token         string `yaml:"token,omitempty"`
	// HN: handle name returned by the hub at register time, derived from the
	// raw token (= "swift-otter-a3f7" style).  Cached here so the admin UI
	// can show it without a hub round-trip.  HNOverride (= empty by default)
	// lets the operator pick a custom display name; the hub keeps the
	// derived HN as the canonical identity, override is presentation-only.
	HN         string `yaml:"hn,omitempty"`
	HNOverride string `yaml:"hn_override,omitempty"`
	// No omitempty: defaults to true, so an operator who opts out (false) would
	// otherwise have it dropped on Save and reverted to true on Load --
	// re-publishing the reporter country against their privacy choice.
	PublishCountry       bool   `yaml:"publish_country"`
	RegisterURL          string `yaml:"register_url,omitempty"`
	SubmitURL            string `yaml:"submit_url,omitempty"`
	FeedURL              string `yaml:"feed_url,omitempty"`
	AggregateURL         string `yaml:"aggregate_url,omitempty"`
	LastPulledAt         int64  `yaml:"last_pulled_at,omitempty"`
	Entries              int    `yaml:"entries,omitempty"`
	TermsAcceptedAt      int64  `yaml:"terms_accepted_at,omitempty"`
	TermsAcceptedVersion int    `yaml:"terms_accepted_version,omitempty"`
	// MapDir: output dir for community-bans-{ipja4,ja4,ip}.map. Empty = Nginx.OutputDir.
	MapDir string `yaml:"map_dir,omitempty"`

	// LocalMutes: install-local opt-out list.  Each entry mutes one hub feed
	// row so it is dropped before WriteMapFiles, even when subscribe_mode =
	// fetch_apply.  Key shape mirrors community_bans entry identity:
	//   "ip_only:<ip>"          (= no JA4)
	//   "ja4_only:<ja4>"        (= no IP)
	//   "ip_ja4:<ip>|<ja4>"     (= both -- pipe-separated)
	// The "共有 BAN" tab toggles entries in / out of this list; the hub copy
	// is untouched (= mute is a local override, not a hub action).
	LocalMutes []string `yaml:"local_mutes,omitempty"`

	// OperatorEndpoint: base URL for the hub-operator API (= the endpoints
	// behind GET/PATCH /api/feed/operator/*).  Only the operator running the
	// hub itself sets this; left empty on every other install (= the operator
	// review screen stays hidden).
	OperatorEndpoint string `yaml:"operator_endpoint,omitempty"`
	// OperatorTokenFile: path to a file containing the bearer token that
	// authorizes the hub-operator API.  Read on each request so rotating the
	// token does not require an admin restart.  Empty disables the screen.
	OperatorTokenFile string `yaml:"operator_token_file,omitempty"`
}

// DefaultCommunityBans*: unmask.sh hub URLs. Overridable (= for running a
// private hub or pointing test environments at a different endpoint).
const (
	DefaultCommunityBansRegisterURL = "https://unmask.sh/api/feed/register"
	DefaultCommunityBansSubmitURL   = "https://unmask.sh/api/feed/submit"
	// FeedURL is the single hub endpoint that ships promoted + reports-only
	// entries together.  WriteMapFiles filters Promoted=true before writing
	// the nginx map files so non-promoted entries stay browse-only.  Local
	// enforcement is map-only (= no copy into unmask_ban); the "共有 BAN"
	// tab is the sole UI for browsing what the hub published.
	DefaultCommunityBansFeedURL      = "https://unmask.sh/api/feed/list.json"
	DefaultCommunityBansAggregateURL = "https://unmask.sh/api/feed/aggregate"
)

// DefaultVersionCheckURL: the unmask.sh endpoint the admin overview polls for
// the latest release + changelog.  Overridable via Settings.VersionCheckURL.
const DefaultVersionCheckURL = "https://unmask.sh/api/version"

// VersionCheckURLResolved returns the effective update-check URL: the default
// when the field is empty, "" when explicitly turned off (so the admin makes no
// outbound call), else the operator's override.
func (s Settings) VersionCheckURLResolved() string {
	if s.VersionCheckDisabled {
		return ""
	}
	if strings.TrimSpace(s.VersionCheckURL) == "" {
		return DefaultVersionCheckURL
	}
	return strings.TrimSpace(s.VersionCheckURL)
}

// Subscribe mode values.
const (
	SubscribeOff        = "off"         // no pull; maps cleared so enforcement stops
	SubscribeFetch      = "fetch"       // pull for the browse list only (no enforce, no auto-apply)
	SubscribeFetchApply = "fetch_apply" // pull + nginx map enforce + auto-apply
)

// ResolvedSubscribeMode: canonical mode string.  Empty / unknown → off.
func (s CommunityBans) ResolvedSubscribeMode() string {
	switch s.SubscribeMode {
	case SubscribeFetch, SubscribeFetchApply, SubscribeOff:
		return s.SubscribeMode
	}
	return SubscribeOff
}

// SubscribeActive: true when the hub feed should be pulled (= fetch or
// fetch_apply).  Gates "should we pull / register".
func (s CommunityBans) SubscribeActive() bool {
	return s.ResolvedSubscribeMode() != SubscribeOff
}

// ApplyActive: true when pulled entries should drive nginx map enforcement +
// auto-apply (= fetch_apply only).  "fetch" pulls for browsing but never
// enforces.
func (s CommunityBans) ApplyActive() bool {
	return s.ResolvedSubscribeMode() == SubscribeFetchApply
}

// ResolvedRegisterURL: returns the default when empty.
func (s CommunityBans) ResolvedRegisterURL() string {
	if s.RegisterURL == "" {
		return DefaultCommunityBansRegisterURL
	}
	return s.RegisterURL
}

// ResolvedSubmitURL: returns the default when empty.
func (s CommunityBans) ResolvedSubmitURL() string {
	if s.SubmitURL == "" {
		return DefaultCommunityBansSubmitURL
	}
	return s.SubmitURL
}

// ResolvedFeedURL: returns the default when empty.
func (s CommunityBans) ResolvedFeedURL() string {
	if s.FeedURL == "" {
		return DefaultCommunityBansFeedURL
	}
	return s.FeedURL
}

// ResolvedAggregateURL: returns the default when empty.  This endpoint is used
// by the bans-page detail expand to fetch all submissions / votes / comments
// for an (ip, ja4) pair without going through the local banlist cache.
func (s CommunityBans) ResolvedAggregateURL() string {
	if s.AggregateURL == "" {
		return DefaultCommunityBansAggregateURL
	}
	return s.AggregateURL
}

// CurrentCommunityBansTermsVersion: bump this any time the user-facing privacy
// or terms wording changes materially.  Operators whose TermsAcceptedVersion
// is below this value need to re-accept before SubmitActive() returns true.
//
// The initial public release ships at 1.  The gate machinery (= TermsStale /
// SubmitActive below) is live but un-armed -- when a future release reworks
// the wording, bump this constant in the same commit that lands the new docs
// and existing acceptors will be funnelled through a re-acceptance banner.
const CurrentCommunityBansTermsVersion = 1

// SubmitActive: submission is allowed only when submit_enabled && terms
// accepted at the current version.  Operators on a stale version see a
// banner + the submit_enabled checkbox refusing to take effect until they
// re-accept.
func (s CommunityBans) SubmitActive() bool {
	return s.SubmitEnabled && s.TermsAcceptedAt > 0 && s.TermsAcceptedVersion >= CurrentCommunityBansTermsVersion
}

// TermsStale: TermsAccepted is non-zero but predates the current version
// (= the operator accepted an older wording and has not yet seen the new
// one).  Used by the settings UI to surface a "please re-accept" banner
// without forcing the operator to flip submit_enabled off and on again.
func (s CommunityBans) TermsStale() bool {
	return s.TermsAcceptedAt > 0 && s.TermsAcceptedVersion < CurrentCommunityBansTermsVersion
}

// Notifications: external webhook notifications (= Slack / Discord / generic).
type Notifications struct {
	Disabled            bool   `yaml:"disabled,omitempty"`
	URL                 string `yaml:"url,omitempty"`
	Format              string `yaml:"format,omitempty"`                 // "slack" | "discord" | "generic"
	SiteLabel           string `yaml:"site_label,omitempty"`             // optional label shown in notifications (e.g., "blog-jp")
	BanEvents           bool   `yaml:"ban_events,omitempty"`             // notify on honeypot / manual ban
	ChallengeBurst      bool   `yaml:"challenge_burst,omitempty"`        // notify when the 5min threshold is exceeded
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
//     (nginx / Apache).
//
// Zone resolution order:
//  1. Scan Zones in index order. Adopt the first zone whose PathPatterns
//     prefix-matches.
//  2. If none match, adopt the Default zone.
//
// challenge_mode (= behavior for clients over the threshold):
//   - "captcha_only"      : straight to CAPTCHA (= compat with v0.1 behavior)
//   - "pow_only"          : PoW only. Lightweight, but robust bots pass through
//   - "pow_then_captcha"  : escalate to CAPTCHA on PoW failure. Chain in late v0.1.
//   - "deny"              : no challenge; immediately 403 block (= for API /
//     paths dedicated to known bots)
//
// v2 layout (= multi-site, post-step-b): per-site scalar overrides were
// dropped because every per-site rate variation can be expressed by adding
// a RateZone with a Site column instead.  Default carries the install-wide
// fallback (= the rate every site sees unless a more-specific zone
// matches).  Zones is a flat list; rows scope themselves with PathPatterns
// + Site, in that order from most-specific to least-specific match.
type RateLimitConfig struct {
	// Default: install-wide fallback rate.  Applied when no zone matches.
	Default RateLimitValues `yaml:"default"`
	// Zones: rate-limit rule rows.  Each carries its own RPM / burst / window
	// / mode + optional PathPatterns + Site filter.  Order matters for the
	// match: the first zone whose PathPatterns and Site both match wins.
	Zones []RateZone `yaml:"zones,omitempty"`
	// Key: which fingerprint to count requests against.
	//   "ip"     : $binary_remote_addr only (= default; behaves like classic limit_req)
	//   "ja4"    : $effective_ja4 only (= one bucket per TLS fingerprint; catches
	//              botnets that rotate through many IPs but share a JA4)
	//   "ip+ja4" : "ip|ja4" compound (= narrowest. Two distinct browsers behind
	//              one NAT IP are counted separately)
	// Empty -> "ip" default.
	Key string `yaml:"key,omitempty"`
	// Deny-page design (theme / copy preset / colors) moved to BrandingValues
	// (DenyRate*) so it follows the per-site appearance record like the logo.
	// PresetsBackfilledAt: unix seconds when the install last had its
	// built-in preset zones backfilled.  Lets BackfillRateLimitPresets()
	// run exactly once per preset family; an operator who deletes a preset
	// after a backfill does NOT see it reappear on the next admin restart.
	PresetsBackfilledAt int64 `yaml:"presets_backfilled_at,omitempty"`
}

// builtInRateLimitPresets returns the zones that BackfillRateLimitPresets
// installs on a one-time basis.  Adding a new preset family later is a
// matter of appending to this slice + bumping the stamp comparison in the
// backfill helper; existing rows are never touched, so an operator's
// edits survive.
func builtInRateLimitPresets() []RateZone {
	return []RateZone{
		{
			Name:           "unmask_admin_login",
			RequestsPerMin: 5,
			// Burst sized so the *first* 5 attempts in a minute clear
			// the limit (= an operator mistype is allowed, not punished
			// with a CAPTCHA on the next keystroke), while the 6th
			// attempt fires the zone.  Burst 0 collapses to the render
			// default (= 50) which is too lenient, so we set this
			// explicitly.
			Burst:     5,
			WindowSec: 60,
			// Both the login and the forgot-password POST are auth-credential
			// endpoints, so they share one per-IP zone: a flood of either —
			// login brute-force, or forgot-password email-spam / reset-token
			// clobbering (AUTH-5) — trips the same 5/min gate.  The admin login
			// zone only covered /admin/login, leaving forgot-password unguarded.
			PathPatterns:  []string{"/unmask/admin/login", "/unmask/admin/forgot-password"},
			ChallengeMode: RateChallengeCaptchaOnly,
		},
	}
}

// BackfillRateLimitPresets adds the built-in preset zones to an existing
// install exactly once.  The "exactly once" guarantee uses
// PresetsBackfilledAt as the marker -- a zero stamp means the install
// has never been backfilled; a non-zero stamp leaves Zones untouched no
// matter what the operator has done in the meantime.
//
// Match is by zone Name so a preset that has been renamed locally also
// counts as "present" (= the operator owns it now).  Returns true when a
// backfill actually changed Zones; callers persist the result and bump
// the stamp.
func (c *RateLimitConfig) BackfillRateLimitPresets(now int64) bool {
	if c.PresetsBackfilledAt > 0 {
		return false
	}
	c.PresetsBackfilledAt = now
	have := make(map[string]bool, len(c.Zones))
	for _, z := range c.Zones {
		have[z.Name] = true
	}
	for _, p := range builtInRateLimitPresets() {
		if have[p.Name] {
			continue
		}
		c.Zones = append(c.Zones, p)
	}
	// Always return true once stamping happens.  Even when every preset
	// zone was already present (= defaults() seeded them on a fresh
	// install), the caller still needs to persist the stamp so the next
	// restart skips this work; otherwise the function would re-enter
	// every boot, walk the list, and decide "no, nothing to do" each
	// time the admin starts.
	return true
}

// RateLimitValues: install-wide scalar parameters reused by both the
// Default block and as the value-type returned by RateZone.AsValues so
// downstream callers stay agnostic of "default vs zone match".  No per-site
// overrides at this level; per-site differences live in the zone Site
// column instead.
type RateLimitValues struct {
	// Name: nginx `limit_req_zone` zone name (alnum + "_").  Default may be
	// empty; render falls back to "unmask_rate".
	Name string `yaml:"name,omitempty"`
	// RequestsPerMin / Burst / WindowSec: the actual rate-limit triple.
	RequestsPerMin int `yaml:"requests_per_min"`
	Burst          int `yaml:"burst"`
	WindowSec      int `yaml:"window_sec,omitempty"`
	// ChallengeMode: behaviour for clients over the threshold.  Empty -> the
	// "pow_then_captcha" recommended chain.
	ChallengeMode string `yaml:"challenge_mode,omitempty"`
}

// ResolveZones: zones visible to the given site.  An empty Site applies to
// every host; a non-empty Site filters to exact match.  Order preserved so
// PathPatterns priority + admin UI ordering both survive.
func (c RateLimitConfig) ResolveZones(site string) []RateZone {
	out := make([]RateZone, 0, len(c.Zones))
	for _, z := range c.Zones {
		if z.Site == "" || z.Site == site {
			out = append(out, z)
		}
	}
	return out
}

// ResolvedWindowSec: 0 -> 60 (= 1-minute window default).
func (v RateLimitValues) ResolvedWindowSec() int {
	if v.WindowSec <= 0 {
		return 60
	}
	return v.WindowSec
}

// ResolvedChallengeMode: empty / invalid -> pow_then_captcha.
func (v RateLimitValues) ResolvedChallengeMode() string {
	if !IsValidRateChallengeMode(v.ChallengeMode) {
		return RateChallengePoWThenCaptcha
	}
	return v.ChallengeMode
}

// Rate-limit key kinds.
const (
	RateLimitKeyIP       = "ip"
	RateLimitKeyJA4      = "ja4"
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

// Deny-page theme values (= the allowlist).  "auto" follows the visitor's OS.
const (
	DenyThemeAuto  = "auto"
	DenyThemeLight = "light"
	DenyThemeDark  = "dark"
)

// IsValidDenyTheme reports whether s is a known deny-page theme.
func IsValidDenyTheme(s string) bool {
	switch s {
	case DenyThemeAuto, DenyThemeLight, DenyThemeDark:
		return true
	}
	return false
}

// RateZone: definition of one named path-scoped rate-limit zone.  Zones
// are install-wide (= no per-site overlay) -- the visitor's site does not
// influence which zone the path falls into.  Per-site scalar parameters
// live in RateLimitValues.
//
// Name: nginx `limit_req_zone` name syntax (= alnum + "_").
// PathPatterns: simple prefix match. e.g. "/api/" matches "/api/foo".
//   - empty list = applies to all paths (= unusual; normally a path zone
//     carries at least one pattern, otherwise it would swallow every
//     request before the default kicks in).
//   - multiple entries: a match against any one selects this zone.
//
// WindowSec: 0 → 60 (= 1-minute window).
// ChallengeMode: empty → "pow_then_captcha" (= recommended chain).
type RateZone struct {
	Name           string   `yaml:"name,omitempty"`
	RequestsPerMin int      `yaml:"requests_per_min"`
	Burst          int      `yaml:"burst"`
	WindowSec      int      `yaml:"window_sec,omitempty"`
	PathPatterns   []string `yaml:"path_patterns,omitempty"`
	ChallengeMode  string   `yaml:"challenge_mode,omitempty"`
	// Site: optional Host filter for this zone.  "" applies to every site;
	// a host string (= normalised via siteFromRequest) limits the zone to
	// requests landing on that vhost.
	Site string `yaml:"site,omitempty"`
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

// ResolveZone returns the effective rate-limit triple for the (path, site)
// pair as a RateLimitValues.  Resolution order:
//  1. Scan Zones in index order.  The first zone whose PathPatterns match
//     AND whose Site filter matches wins ("" Site applies to every host).
//  2. Otherwise return the install-wide Default verbatim.
//
// Per-site rate variations are expressed by adding zones with a Site
// column; the pre-v2 per-site Sites map was dropped because the same
// effect was reachable through zones with less mental overhead.
func (c RateLimitConfig) ResolveZone(path, site string) RateLimitValues {
	for _, z := range c.Zones {
		if z.Site != "" && z.Site != site {
			continue
		}
		if z.MatchPath(path) {
			return RateLimitValues{
				Name:           z.Name,
				RequestsPerMin: z.RequestsPerMin,
				Burst:          z.Burst,
				WindowSec:      z.WindowSec,
				ChallengeMode:  z.ChallengeMode,
			}
		}
	}
	return c.Default
}

func defaults() Settings {
	return Settings{
		EventsRetentionDays:   30,
		AuditRetentionDays:    90,
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
		Challenge: ChallengeConfig{
			Default: ChallengeValues{
				PowCookieValidSeconds:     86400 * 7,  // 7 days — automatic proof, refresh more often
				CaptchaCookieValidSeconds: 86400 * 14, // 14 days — human-effort proof, keep longer
				DebugRateLimitPer5Min:     20,
				Theme:                     "default",
				CaptchaProvider: Captcha{
					Provider:              "builtin",
					BuiltinScoreThreshold: 0.5,
					RecaptchaMinScore:     0.5,
				},
			},
		},
		Branding: Branding{
			Default: BrandingValues{
				// Default copy preset is "friendly" — strictly better than
				// the old "Verifying your browser…" baseline that triggered
				// "is my browser infected?" confusion in real users.  Logo /
				// site name / footer stay blank until the operator fills them
				// in via the branding panel.
				CopyPreset: BrandingPresetFriendly,
			},
		},
		RateLimit: RateLimitConfig{
			// The Default record applies to every site that has no entry in
			// RateLimit.Sites.  100r/m + burst 50.  Challenge mode is
			// pow_then_captcha (= recommended chain): stall with PoW + verify
			// with CAPTCHA.  Legitimate users typically only need PoW.
			Default: RateLimitValues{
				Name:           "unmask_rate",
				RequestsPerMin: 100,
				Burst:          50,
				WindowSec:      60,
				ChallengeMode:  RateChallengePoWThenCaptcha,
			},
			// Preset zones are seeded via BackfillRateLimitPresets on the first
			// admin start (= idempotent, stamp guarded).  Keeping defaults()
			// zone list empty lets e2e admin.yml load without the preset
			// triggering Save() side-effects in fresh-install code paths.
		},
		Global: GlobalConfig{
			// Known browsers get a transparent first-visit PoW by default
			// (pow_only).  Even a real-browser UA can be a bot that mimics a
			// browser JA4 + UA closely enough to pass the axes, so out of the
			// box every no-match request is gated with a PoW a script can't
			// solve -- defense in depth behind the JA4 axis.  One solve sets the
			// _bv cookie and the rest of its validity window sails through, so a
			// genuine user only feels it on the first visit.  Set
			// known_browser_action: pass to instead let JA4-confirmed real
			// browsers through with zero friction (trades depth for UX).
			// Unknown UAs likewise PoW, via the empty UnknownUAAction.
			KnownBrowserAction: "pow_only",
		},
		Server: Server{
			Bind:     "127.0.0.1",
			Port:     9477,
			BasePath: "/unmask",
		},
		NginxLog: NginxLog{
			Enabled:    true,
			SocketPath: "/run/unmask/log.sock",
		},
		// IPGeo default points at the unmask-scoped install path that
		// `unmask install-ipgeo` writes to.  The file is NOT bundled
		// (= DB-IP Lite is dl on demand); if it doesn't exist, ipgeo.Reader
		// quietly stays in "no DB" mode and the geo axis short-circuits to
		// silent.  Once install-ipgeo runs, admin's next reload picks it up.
		IPGeo: IPGeo{
			MMDBPath: "/var/lib/unmask/ipgeo/dbip-country.mmdb",
			// ASN DB is optional but defaults to the DB-IP managed path so
			// the network tab's ASN radio pre-selects "DB-IP".  Users who
			// pick "none" get this cleared on save.
			MMDBASNPath: "/var/lib/unmask/ipgeo/dbip-asn.mmdb",
			AutoFetch:   true,
		},
		CommunityBans: CommunityBans{
			SubmitEnabled: false,
			// Subscribe + auto-apply the shared feed out of the box (secure by
			// default, in line with the challenge-by-default posture).  The
			// enforcement surface is guarded: only promoted (judged, high-score)
			// entries are written to the nginx maps, and whitelisted-crawler IPs
			// (Googlebot / Bingbot / GPTBot ranges, internal LBs) are stripped
			// before enforcement (the search-engine-accident guard), so the
			// classic "blocked a search bot" failure can't happen here.
			// Submitting (sharing this install's own bans) stays opt-in behind
			// the terms acceptance; only the consume side defaults on.
			SubscribeMode:  SubscribeFetchApply,
			PublishCountry: true, // reporter-side country code on by default so the feed shows a global picture; opt-out remains available in the settings UI
			RegisterURL:    DefaultCommunityBansRegisterURL,
			SubmitURL:      DefaultCommunityBansSubmitURL,
			FeedURL:        DefaultCommunityBansFeedURL,
			AggregateURL:   DefaultCommunityBansAggregateURL,
		},
		Nginx: Nginx{
			// /var/lib/ rather than /etc/ because everything below this point
			// is admin-rendered (= DO NOT EDIT) -- /etc/ is reserved for the
			// hand-edited config.yml per FHS.  Future apache support will live
			// at /var/lib/unmask/apache/ alongside /var/lib/unmask/nginx/.
			OutputDir: "/var/lib/unmask/nginx",
			// UpstreamAddr stays empty so buildUpstreamServer derives the
			// upstream from server.bind (TCP or unix:).  An operator deploys
			// admin and nginx in separate network namespaces (= docker
			// compose, k8s) can set it explicitly to e.g. "admin:9477".
			SeenVersion: "v0.1", // baseline for new-preset NEW-badge gating
			// AdminAllowedIPs defaults to empty = NO IP restriction on the
			// admin UI (login + CSRF + login rate-limit still apply).  The
			// wizard intentionally leaves it empty — an auto-guessed CIDR
			// would lock a roaming operator out of the UI needed to fix it —
			// so restricting it is a documented post-setup operator step
			// (settings → nginx).  Enforcement lives in
			// handlers.AdminIPAllowMiddleware, not in the rendered nginx conf.
			AdminAllowedIPs:  nil,
			MetricsAllowFrom: nil,
			// All shipped crawler IP-range presets are ON by default -- this is
			// the "search bot rescue" safety net required by the CLAUDE.md
			// design principle: always let search bots through.  Operators uncheck a row
			// in the UI to drop its ID from this list.  When a new preset is
			// added in a later release it ships with isNew=true and stays OFF
			// until the operator opts in (= SeenVersion gate).
			BypassIPEnabledPresets: []string{
				"google-common", "google-special", "google-user-triggered",
				"bing", "duckduckbot",
				"openai-gptbot", "openai-searchbot", "openai-chatgpt-user",
				"perplexitybot",
				"chrome-prefetch-proxy",
			},
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
				BanFilePath: "/var/lib/unmask/nginx/banned.txt",
				// DefaultAction left empty -> inherits the same fallback as
				// the rate-limit default (pow_then_captcha).  Keeps the
				// chain choice consistent across axes.
				BanDurationSec: 86400, // 24h
			},
			ProtectedPaths: ProtectedPathsConfig{
				// "unmask" preset enabled by default: covers /unmask/admin/
				// with a CAPTCHA gate layered on top of the IP allow-list.
				// Path is fixed by unmask itself, no site-layout risk.
				// "common-admin" stays opt-in because its patterns (= /wp-admin/
				// etc.) depend on what the protected site actually serves.
				EnabledPresets: []string{"unmask"},
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

// RawBVSecretPresent reports whether the config FILE at path sets a non-empty
// secret.bv_secret, BEFORE Load()'s random fill-in.  doctor uses it to flag a
// config that omits the secret: Load would otherwise fabricate a per-process
// key (different in every process), so render-nginx and the daemon disagree
// and the challenge loops forever — while a post-Load check sees a 24-char
// value and reports a false green.  A missing / unreadable / unparsable file
// returns false (= treat as "not set"); doctor's own config-load check reports
// the read error separately.
func RawBVSecretPresent(path string) bool {
	raw, err := os.ReadFile(ResolvePath(path))
	if err != nil {
		return false
	}
	var probe struct {
		Secret struct {
			BVSecret string `yaml:"bv_secret"`
		} `yaml:"secret"`
	}
	if yaml.Unmarshal(raw, &probe) != nil {
		return false
	}
	return strings.TrimSpace(probe.Secret.BVSecret) != ""
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
		// Strict re-parse into a throwaway, purely to surface keys the loader
		// silently ignored: a misplaced challenge knob (flat under `challenge:`
		// instead of `challenge.default:`) or a typo'd field would otherwise be
		// dropped without a trace.  Warn, never fail -- unknown keys from older
		// versions must still load (feedback_no_user_rescue).
		probeDec := yaml.NewDecoder(strings.NewReader(string(raw)))
		probeDec.KnownFields(true)
		var probe Settings
		if perr := probeDec.Decode(&probe); perr != nil {
			log.Printf("unmask: config %s has unrecognized or misplaced keys (ignored, defaults used): %v", resolved, perr)
		}
	}
	if s.Secret.BVSecret == "" {
		// Neither config.yml nor config-init supplied a key.  A per-process
		// random key makes render-nginx and the daemon sign / verify _bv with
		// different keys, looping every visitor; instead persist one to a
		// sidecar so every process that loads this config converges on it (DB-5).
		sec, persisted := loadOrCreateBVSecret()
		s.Secret.BVSecret = sec
		if persisted {
			log.Printf("unmask: secret.bv_secret was unset in %q — using an auto-generated key persisted to %s so render-nginx and the daemon share it. Set secret.bv_secret explicitly or run `unmask config-init` to silence this.", resolved, bvSecretSidecarPath())
		} else {
			log.Printf("unmask: WARNING: secret.bv_secret is not set in %q and the auto-generated key could NOT be persisted (%s unwritable) — render-nginx and the daemon will sign _bv with different keys and every visitor loops on the challenge. Set a fixed secret.bv_secret or run `unmask config-init`.", resolved, bvSecretSidecarPath())
		}
	}
	if s.Secret.CaptchaSecretBase == "" {
		s.Secret.CaptchaSecretBase = randomHex(24)
	}
	BackfillExtraVerdictIDs(&s)
	// Rate-limit preset backfill, stamp persisted to a sibling file so
	// the "do not reappear after operator delete" guarantee survives a
	// restart.  yaml.Marshal-backed Save() can't be used (= clobbers
	// intentionally-sparse admin.yml overrides like the honeypot URL
	// preset list -- see feedback_settings_load_no_save), so the stamp
	// is its own one-line file under the runtime state dir.
	rateLimitPresetBackfill(&s.RateLimit, time.Now().Unix())
	return s, nil
}

// presetBackfillStampPath returns where the one-shot stamp lives.  Kept
// next to the runtime state (= /var/lib/unmask) rather than under /etc
// so the file is mode-600 writable by the admin uid without sudo and
// the operator's config dir stays read-only-by-policy.
func presetBackfillStampPath() string {
	return "/var/lib/unmask/preset-backfill.stamp"
}

// rateLimitPresetBackfill runs the in-memory backfill exactly once per
// install, gated on a stamp file.  On first invocation it appends the
// built-in preset zones, writes the timestamp, and returns; subsequent
// starts read the stamp + skip both the append and the file write so
// an operator who deleted the preset zone in the UI sees no resurrection.
//
// A failed read / write is non-fatal: the worst case is that the
// backfill re-runs next start, which is idempotent (= dedup by zone
// name) and harmless.
func rateLimitPresetBackfill(rl *RateLimitConfig, now int64) {
	stampPath := presetBackfillStampPath()
	if data, err := os.ReadFile(stampPath); err == nil {
		ts := strings.TrimSpace(string(data))
		if ts != "" {
			// Mirror the stamp into the in-memory struct so the UI
			// "last backfilled" display stays accurate even though
			// the yaml never persisted it.
			if v, perr := strconv.ParseInt(ts, 10, 64); perr == nil {
				rl.PresetsBackfilledAt = v
				return
			}
		}
	}
	// First start (= no stamp file).  Run the backfill, persist the
	// timestamp.  BackfillRateLimitPresets sets PresetsBackfilledAt on
	// the struct itself; we copy that value into the stamp file.
	if !rl.BackfillRateLimitPresets(now) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(stampPath), 0o755); err == nil {
		_ = os.WriteFile(stampPath, []byte(strconv.FormatInt(rl.PresetsBackfilledAt, 10)+"\n"), 0o644)
	}
}

// bvSecretSidecarPath returns where an auto-generated _bv HMAC key is persisted
// so render-nginx (CLI) and the daemon -- separate processes that each call
// Load -- converge on ONE key instead of each inventing its own and looping
// every visitor (DB-5).  Lives next to runtime state (= writable by the admin
// uid without sudo) and is mode-0600 because it is a signing secret (NOT 0644
// like the preset stamp -- a world-readable bv_secret leaks the _bv key).
func bvSecretSidecarPath() string {
	return "/var/lib/unmask/bv_secret"
}

// loadOrCreateBVSecret returns a persisted _bv key for the case where config.yml
// omits one.  It reads the sidecar if present so every process shares the same
// key; on first call it generates one and writes it 0600.  A read/write failure
// falls back to a per-process key (= the pre-DB-5 behavior) and reports
// persisted=false so the caller can warn that the loop is still possible.
func loadOrCreateBVSecret() (secret string, persisted bool) {
	p := bvSecretSidecarPath()
	if data, err := os.ReadFile(p); err == nil {
		if sec := strings.TrimSpace(string(data)); sec != "" {
			return sec, true
		}
	}
	sec := randomHex(24)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
		if err := os.WriteFile(p, []byte(sec+"\n"), 0o600); err == nil {
			return sec, true
		}
	}
	return sec, false
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
func (c ChallengeValues) CookieMaxAgeSeconds() int { return BrowserCookieMaxAgeSeconds }

// PowCookieValidSecondsResolved: PowCookieValidSeconds if set, else 7 days.
func (c ChallengeValues) PowCookieValidSecondsResolved() int {
	if c.PowCookieValidSeconds > 0 {
		return c.PowCookieValidSeconds
	}
	return 86400 * 7
}

// CaptchaCookieValidSecondsResolved: CaptchaCookieValidSeconds if set, else 14 days.
func (c ChallengeValues) CaptchaCookieValidSecondsResolved() int {
	if c.CaptchaCookieValidSeconds > 0 {
		return c.CaptchaCookieValidSeconds
	}
	return 86400 * 14
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
// WithSecretsRedacted returns a copy with secret fields blanked, for the
// settings EXPORT / audit display.  bv_secret is the admin session-signing key
// (session.go), so an unredacted export lets an admin-role downloader forge a
// superadmin session and mint _bv bypass cookies for every site; the rest are
// credentials.  Only scalar string fields are touched, so the value-receiver
// copy fully isolates the original.  Keep in sync with the index page masks.
func (s Settings) WithSecretsRedacted() Settings {
	const r = "***REDACTED***"
	redact := func(p *string) {
		if *p != "" {
			*p = r
		}
	}
	redact(&s.Secret.BVSecret)
	redact(&s.Secret.CaptchaSecretBase)
	redact(&s.DB.MariaDB.Password)
	redact(&s.SMTP.Password)
	redact(&s.CommunityBans.Token)
	return s
}

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
		"# unmask config (= managed by unmask web UI; do not edit while admin running)\n" +
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
