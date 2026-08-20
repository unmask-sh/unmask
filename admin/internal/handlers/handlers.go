// Package handlers contains the net/http handlers bound to the ServeMux by app.go.
package handlers

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/browsermajors"
	"github.com/unmask-sh/unmask/admin/internal/captcha"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/crawlerverify"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/mail"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/nginxlog"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"github.com/unmask-sh/unmask/admin/internal/privacypass"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
	"github.com/unmask-sh/unmask/admin/internal/webbotauth"
)

const (
	challengePlaceholder = `/*__CAPTCHA_FORCE__*/"none"`
	challengeProbe       = "<!--__SUBFILTER_PROBE__-->"
	captchaPlaceholder   = "/*__CAPTCHA__*/null"
	themePlaceholder     = `/*__THEME__*/"auto"`
	// customColors / customAutoColors: the per-theme recolor pair.  For a named
	// theme it is {bg,text}; for "auto" the OS-resolved palette is client-side so
	// customAutoColors carries {light:{bg,text},dark:{bg,text}} and the inline
	// bootstrap picks the matching one.
	customColorsPlaceholder     = `/*__CUSTOM__*/null`
	customAutoColorsPlaceholder = `/*__CUSTOM_AUTO__*/null`
	brandingPlaceholder         = `/*__BRANDING__*/null`
	buildVPlaceholder           = `__BUILD_V__`
	// The external challenge.js <script> tag.  ServeChallenge inlines the JS
	// verbatim in its place so a client that cannot fetch the 53KB external file
	// (an extension / flaky network / odd proxy) never loops on a challenge
	// whose PoW never ran -- the widespread tool1-jp loop.
	challengeJSScriptTag = `<script src="/unmask/static/challenge.js?v=__BUILD_V__" defer></script>`
	chmodePlaceholder    = `/*__CHMODE__*/"pow_then_captcha"`
	powDiffPlaceholder   = "/*__POW_DIFFICULTY__*/18"
	// PoW display floor (visible style).  The HTML's own value 0 means "no
	// floor" if substitution ever fails; the handler injects the resolved
	// ChallengeValues.MinDisplayMS (default 800), and the /unmask/test/
	// pages can override it via `?_pow_display=N` for visual inspection.
	powMinDisplayMsPH = "/*__POW_MIN_DISPLAY_MS__*/0"
	// Challenge display style + the invisible style's timing knobs.  The
	// style is injected twice by one ReplaceAll: into an inline <head> script
	// (so the CSS hides the card BEFORE first paint -- a deferred script
	// would flash the content it is about to hide) and into window.UNMASK.
	challengeStylePH        = `/*__CHALLENGE_STYLE__*/"visible"`
	invisibleRevealPH       = "/*__INVISIBLE_REVEAL_MS__*/1200"
	revealFadePH            = "/*__REVEAL_FADE_MS__*/200"
	origPathPlaceholder     = `/*__ORIG_PATH__*/""`
	beaconTokenPlaceholder  = `/*__BEACON_TOKEN__*/""`
	serveJA4Placeholder     = `/*__SERVE_JA4__*/""`
	issuedAtPlaceholder     = `/*__ISSUED_AT__*/0`
	powSeedPlaceholder      = `/*__POW_SEED__*/""`
	ctTokenPlaceholder      = `/*__CT__*/""`
	bvMaxEntriesPlaceholder = `/*__BV_MAX_ENTRIES__*/8`
	// refPlaceholder marks where challenge.html's footer prints the support
	// correlation id.  Unlike the JS-literal placeholders above this sits in the
	// HTML body as a comment, so an un-substituted build (or a stripped footer)
	// degrades to invisible rather than leaking the token text.  The substituted
	// value is bare hex + a dash, so no HTML escaping is required.
	refPlaceholder = "<!--__REF__-->"
	defaultSite    = "default"
)

// challengeThemes is the allowlist applied to the challenge page.  ?theme=
// query and settings value are applied only if they belong to this set
// (prevents XSS / unknown class injection).
var challengeThemes = map[string]bool{
	"light":    true,
	"dark":     true,
	"auto":     true, // follows the visitor's OS: light / dark per prefers-color-scheme
	"terminal": true,
	"cat":      true,
	"paper":    true,
}

// pickChallengeTheme picks one in the order ?theme= query (preview) >
// settings > "auto", validates against the allowlist, and returns it.
func pickChallengeTheme(r *http.Request, configured string) string {
	if q := strings.TrimSpace(r.URL.Query().Get("theme")); q != "" {
		if challengeThemes[q] {
			return q
		}
	}
	if challengeThemes[configured] {
		return configured
	}
	return "auto" // out-of-the-box default: follow the visitor's OS (light/dark)
}

// challengeThemeBaseColors are the built-in [bg, text] of each recolorable theme.
// Used by the settings theme tab to pre-fill the per-theme color inputs so the
// operator edits from the theme's own look.  "auto" is absent (it composes
// light + dark).  cat's real background is a gradient; the value here is a
// representative solid for the picker default (an override replaces the gradient
// with a solid).  Keep in sync with the body.theme-* rules in challenge.html.
var challengeThemeBaseColors = map[string][2]string{
	"light":    {"#f0f2f5", "#333333"},
	"dark":     {"#0d1117", "#c9d1d9"},
	"terminal": {"#050807", "#5cd0a8"},
	"paper":    {"#faf6ed", "#1a1715"},
	"cat":      {"#ffd0c4", "#3a2a1c"},
}

type Handler struct {
	DB *db.DB
	// settingsPtr holds the live settings snapshot.  Read it lock-free via
	// cfg() — race-free because writers publish a fresh *settings.Settings with
	// Store while readers Load a stable pointer (no torn struct).  Writers
	// serialize through settingsMu and publish via SetSettings /
	// updateSettingsInMemory / the save handlers.
	settingsPtr   atomic.Pointer[settings.Settings]
	ConfigPath    string                  // settings save target (the web editing UI atomic-writes here).  Empty -> cannot save.
	Version       string                  // unmask version (for display)
	HostID        string                  // host identifier of this unmask instance.  Embedded in events for per-host aggregation on a shared DB.
	IPGeo         *ipgeo.Reader           // optional, may be nil/empty (mmdb unset)
	CrawlerVerify *crawlerverify.Verifier // optional; nil disables rDNS crawler auth
	NginxLog      *nginxlog.Reader        // optional, may be nil/empty (access_log_path unset)
	BanMgr        *ban.Manager            // optional, may be nil (ban_file_path unset)
	UserRepo      *user.Repository        // internal user management (login / users tab / audit hook)
	// loginThrottle guards the credential endpoints (login / forgot-password)
	// against per-IP hammering.  Accessed via throttle(); the Once lets the
	// zero-value Handler used all over the tests keep working.
	loginThrottle     *loginThrottle
	loginThrottleOnce sync.Once
	Notifier          *notifier.Notifier    // optional, may be nil (notification URL unset)
	Mailer            *mail.Mailer          // optional, may be nil (SMTP unset).  Used by alert / password reset.
	RateLimiter       *ratelimit.Limiter    // sliding-window counter for forward-auth mode.  nil disables counting.
	CommunityBans     *communitybans.Client // optional, may be nil.  Async submit to community feed on BAN + periodic pull.
	IPRangeSync       *nginxconf.Sync       // optional, may be nil.  Subscribe loop that pulls bypass-IP prefixes from the hub.
	BrowserSync       *browsermajors.Sync   // optional, may be nil.  Subscribe loop that pulls stale-browser baselines from the hub.
	WebBotAuth        *webbotauth.Verifier  // optional, may be nil.  RFC 9421 signature verification for bot requests.
	PrivacyPass       *privacypass.Verifier // optional, may be nil.  Privacy Pass / PAT (RFC 9577/9578) token verification.

	// overBlockTripped is the over-block circuit breaker state, sampled and set
	// by RunOverBlockMonitor (over_block.go) and read in ServeChallenge.
	overBlockTripped atomic.Bool

	// communityHits caches the "Community Bans impact" 30-day figures -- the
	// query scans the whole 30-day serve window, far too slow per page load.
	// See community_hits.go.
	communityHits communityHitsCache

	// previewLogos holds ephemeral logo uploads for the settings live preview
	// (token -> image bytes).  Populated by PreviewLogoUpload, read by
	// PreviewLogoServe, age/count-evicted; lazily created via
	// previewLogoStoreOf.  Nil until the first preview upload.
	previewLogos atomic.Pointer[previewLogoStore]
}

// cfg returns the live settings snapshot.  The returned pointer is shared and
// MUST be treated as read-only — never mutate a field through it.  Lock-free
// and race-free against concurrent publishers.  Nil-safe: a zero-value Handler
// yields an empty (default) config rather than panicking.
func (h *Handler) cfg() *settings.Settings {
	if p := h.settingsPtr.Load(); p != nil {
		return p
	}
	return &settings.Settings{}
}

// SetSettings atomically publishes a full settings snapshot.  Used for startup
// wiring and by tests; the live web-save handlers swap via Store under
// settingsMu.  The value is copied into the parameter, so the stored pointer is
// never aliased by the caller.
func (h *Handler) SetSettings(s settings.Settings) { h.settingsPtr.Store(&s) }

// updateSettingsInMemory applies mutate to a copy of the current settings and
// atomically publishes the result.  In-memory only (no disk persist); writers
// serialize through settingsMu.  Used by the setup wizard's runtime hot-swap
// and by tests — the web save path persists to disk then swaps separately.
func (h *Handler) updateSettingsInMemory(mutate func(*settings.Settings)) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	cur := *h.cfg()
	mutate(&cur)
	h.settingsPtr.Store(&cur)
}

// Allowed characters for site name: lowercase alnum + dash, 1-32 chars, no leading/trailing dash.
var siteIDRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)

// pickSite reads r.PathValue("site") and validates it.  Empty / invalid -> "default".
// If an invalid value arrives, returns ok=false so the caller can return 400.
func pickSite(r *http.Request) (site string, ok bool) {
	s := r.PathValue("site")
	if s == "" {
		return defaultSite, true
	}
	if !siteIDRE.MatchString(s) {
		return "", false
	}
	return s, true
}

// captchaSecretFor returns the secret_key for the given provider (internal routing).
func captchaSecretFor(c settings.Captcha) string {
	switch c.Provider {
	case "turnstile":
		return c.TurnstileSecretKey
	case "hcaptcha":
		return c.HCaptchaSecretKey
	case "recaptcha":
		return c.RecaptchaSecretKey
	}
	return ""
}

// captchaInjectJSON returns the JSON embedded into window.UNMASK.captcha
// inside the challenge HTML.
//
// builtin (the unmask default) returns "null" because it uses no external
// widget — challenge.js performs the usual behavioral check.
//
// 3rd party returns { provider, site_key }.  Never emit secret_key (only the
// server is allowed to hold it).
func captchaInjectJSON(c settings.Captcha) string {
	if c.Provider == "" || c.Provider == "builtin" {
		return "null"
	}
	var siteKey string
	switch c.Provider {
	case "turnstile":
		siteKey = c.TurnstileSiteKey
	case "hcaptcha":
		siteKey = c.HCaptchaSiteKey
	case "recaptcha":
		siteKey = c.RecaptchaSiteKey
	}
	if siteKey == "" {
		// site_key unset = provider config incomplete -> fall back to builtin.
		return "null"
	}
	// Simple string escaping suffices (site_key validation should only accept base64-style).
	type out struct {
		Provider string `json:"provider"`
		SiteKey  string `json:"site_key"`
	}
	b, err := json.Marshal(out{Provider: c.Provider, SiteKey: siteKey})
	if err != nil {
		return "null"
	}
	return string(b)
}

// buildVersionStamp is set at admin start (= time.Now().Unix()) and is
// rendered into challenge.html as a `?v=...` query on the <script src>.
// Each restart breaks visitor-side caching of challenge.js so a UI fix
// propagates without waiting for the 10-minute Cache-Control window.
var buildVersionStamp = time.Now().Unix()

// brandingInjectJSON builds the JSON object embedded in challenge.html.
// challenge.js reads window.__brand and applies logo / site_name / footer /
// copy preset.  Returns "null" when branding is disabled or carries no info
// worth sending — keeps the visitor payload minimal in the common case.
//
// logo_url is built from the configured logo file's extension (e.g. .svg /
// .png) so the browser fetches /<base>/branding/logo.<ext>; an empty path
// omits the field and the JS hides the <img> slot.
// logoSite, when non-empty, points the logo URL at the site-scoped serve route
// (/branding/<site>/logo) so a test-page site preview fetches THAT site's logo
// rather than the physical host's (the plain /branding/logo route resolves the
// request host's branding).  Empty for normal traffic.
func brandingInjectJSON(b settings.BrandingValues, basePath, logoURLOverride string, suppressLogo bool, logoSite string) string {
	type out struct {
		LogoURL    string `json:"logo_url,omitempty"`
		SiteName   string `json:"site_name,omitempty"`
		FooterText string `json:"footer_text,omitempty"`
		CopyPreset string `json:"copy_preset"`
	}
	o := out{
		SiteName:   strings.TrimSpace(b.SiteName),
		FooterText: strings.TrimSpace(b.FooterText),
		CopyPreset: b.ResolvedCopyPreset(),
	}
	// logoURLOverride is the settings live-preview path: a not-yet-saved logo
	// served from the ephemeral preview store.  When set it wins over the saved
	// LogoPath so the challenge preview iframe shows the picked image at once.
	// suppressLogo previews the "removed" state (operator clicked remove but
	// hasn't saved): no logo even though one is still saved on disk.
	switch {
	case suppressLogo:
		// leave o.LogoURL empty
	case logoURLOverride != "":
		o.LogoURL = logoURLOverride
	case strings.TrimSpace(b.LogoPath) != "":
		p := strings.TrimSpace(b.LogoPath)
		ext := strings.ToLower(filepath.Ext(p))
		// Allowlist of extensions we will actually serve.  Anything else is
		// treated as "no logo" so a stale config doesn't trip the visitor.
		switch ext {
		case ".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif":
			base := strings.TrimRight(basePath, "/")
			url := base + "/branding/logo"
			if logoSite != "" {
				url = base + "/branding/" + logoSite + "/logo"
			}
			// Cache-bust via mtime so a new upload propagates to visitors
			// without waiting for the 5-min Cache-Control max-age.
			if st, err := os.Stat(p); err == nil {
				url += "?v=" + strconv.FormatInt(st.ModTime().Unix(), 10)
			}
			o.LogoURL = url
		}
	}
	// Skip the payload entirely when there's nothing to override (= the
	// visitor still benefits from the friendlier default copy preset,
	// applied client-side from window.__brand defaults).
	if o.LogoURL == "" && o.SiteName == "" && o.FooterText == "" && o.CopyPreset == settings.BrandingPresetFriendly {
		return "null"
	}
	js, err := json.Marshal(o)
	if err != nil {
		return "null"
	}
	return string(js)
}

// ServeBrandingLogo: GET {base}/branding/logo.<ext>.  Reads the configured
// logo file from disk, sniffs the file extension to pick a Content-Type, and
// streams the bytes back.  Public (no auth) — the logo is visitor-facing.
// 404 when branding is disabled or no logo is configured; a path/extension
// mismatch (e.g. visitor asks for .png but operator stored .svg) is also a
// 404 so cached URLs cannot fall through to a different file.
func (h *Handler) ServeBrandingLogo(w http.ResponseWriter, r *http.Request) {
	cfg := h.snapshotSettings()
	// The site-scoped route (/branding/{site}/logo) previews another site's
	// logo for an authorized test-page caller (admin session, or the public
	// site picker opt-in) — same gate as the site-scoped challenge/verify.  An
	// unauthorized caller, or the plain /branding/logo route, resolves the
	// request host's branding as before.
	site := siteFromRequest(r, cfg)
	if o, ok := h.testSiteOverride(r); ok {
		site = o
	}
	b := cfg.Branding.Resolve(site)
	if strings.TrimSpace(b.LogoPath) == "" {
		http.NotFound(w, r)
		return
	}
	ext := strings.ToLower(filepath.Ext(b.LogoPath))
	data, err := os.ReadFile(b.LogoPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch ext {
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
		// An uploaded SVG can embed <script>/on*/<foreignObject>; served as a
		// top-level document (not via <img>, which sandboxes it) that would run.
		// A logo needs no script/object/external fetch, so lock it down with CSP
		// rather than parsing+sanitizing the XML (L-C1).
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	case ".webp":
		w.Header().Set("Content-Type", "image/webp")
	case ".gif":
		w.Header().Set("Content-Type", "image/gif")
	default:
		http.NotFound(w, r)
		return
	}
	// Short cache to ride out a flurry of visitor requests but still let a
	// freshly-uploaded logo propagate within minutes.
	w.Header().Set("Cache-Control", "public, max-age=300")
	if _, err := w.Write(data); err != nil {
		return
	}
}

// basePath returns the configured admin base URL prefix without a trailing
// slash. Used when assembling visitor-facing URLs (e.g. the logo URL embedded
// in challenge.html).
func (h *Handler) basePath() string {
	return strings.TrimRight(h.cfg().Server.BasePath, "/")
}

// loadChallengeHTML returns the challenge.html bytes.  Order:
//
//   - settings.challenge.challenge_html_path (the operator named a file)
//   - embedded assets/static/challenge.html (default)
//
// The packaged copy under /usr/share/unmask/challenge/ is NOT consulted.  It
// used to win automatically, which made it a trap rather than a convenience:
// the package writes it at install time, so after an upgrade that replaced only
// the binary the visitor kept being served the previous release's page, with
// nothing in the UI to say so.  It is still shipped, as the file to copy and
// point challenge_html_path at.

// ignoredAssetOnce keeps the notice below to one line per path for the life of
// the process.  These loaders run on every challenge served, and a warning
// repeated at that rate is a log nobody can read rather than a warning.
var ignoredAssetOnce onceByKey

type onceByKey struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (o *onceByKey) Do(key string, f func()) {
	o.mu.Lock()
	if o.seen == nil {
		o.seen = map[string]bool{}
	}
	first := !o.seen[key]
	o.seen[key] = true
	o.mu.Unlock()
	if first {
		f()
	}
}

// challengeHTMLPackagePath is where the package drops its reference copy.  Read
// only to notice an edited one and say it is being ignored; a package var so
// tests can point it elsewhere.
var challengeHTMLPackagePath = "/usr/share/unmask/challenge/challenge.html"

func (h *Handler) loadChallengeHTML() ([]byte, error) {
	// challenge_html_path is treated as a global override (= same template
	// for every site).  Per-site challenge HTML override is out of scope for
	// v0.1 -- branding / preset / theme already cover the typical needs.
	if p := h.cfg().Challenge.Default.ChallengeHTMLPath; p != "" {
		return os.ReadFile(p)
	}
	// A packaged /usr/share/unmask/challenge/challenge.html that predates the
	// seed-bound PoW (no __POW_SEED__ placeholder) makes every visitor loop:
	// challenge.js solves a seedless PoW the current plugin rejects, so no _bv
	// ever verifies.  This actually shipped to tool1 -- a 2026-05-25 asset left
	// in place across a plugin upgrade looped every real visitor.  Require the
	// placeholder before trusting the on-disk copy; otherwise fall back to the
	// embedded (always-current) one rather than serving a challenge that can
	// never be solved.
	b, err := assets.Static.ReadFile(filepath.ToSlash("static/challenge.html"))
	if err != nil {
		return nil, err
	}
	warnIgnoredPackagedAsset(challengeHTMLPackagePath, "challenge_html_path", b)
	return b, nil
}

// challengeJSPackagePath is the package-deployed challenge.js override; a
// package var so tests can point it at a stale fixture.
var challengeJSPackagePath = "/usr/share/unmask/challenge/challenge.js"

// loadChallengeJS returns the challenge.js bytes, mirroring loadChallengeHTML:
// the operator's challenge_js_path if set, else the embedded copy.  Used by
// ServeChallengeJS and the inline path.
func (h *Handler) loadChallengeJS() ([]byte, error) {
	if p := h.cfg().Challenge.Default.ChallengeJSPath; p != "" {
		return os.ReadFile(p)
	}
	b, err := assets.Static.ReadFile(filepath.ToSlash("static/challenge.js"))
	if err != nil {
		return nil, err
	}
	warnIgnoredPackagedAsset(challengeJSPackagePath, "challenge_js_path", b)
	return b, nil
}

// warnIgnoredPackagedAsset says once, per path, that an edited copy under
// /usr/share/unmask/challenge/ is not being served.
//
// Silence would be the wrong kindness here.  An operator who customised that
// file -- which the packaging invited, and which the daemon used to honour --
// would otherwise see their edit simply stop applying, with the page looking
// correct and nothing anywhere explaining it.  A copy that still matches what
// this build embeds is the package's own default and says nothing.
func warnIgnoredPackagedAsset(path, setting string, embedded []byte) {
	ignoredAssetOnce.Do(path, func() {
		b, err := os.ReadFile(path)
		if err != nil || bytes.Equal(b, embedded) {
			return
		}
		log.Printf("unmask: %s differs from the built-in copy and is NOT being served; "+
			"set challenge.%s to that path to use it", path, setting)
	})
}

// stripOrKeepCredit processes the
// <!--UNMASK_CREDIT_START-->...<!--UNMASK_CREDIT_END--> segment of
// challenge.html based on settings.Challenge.ShowCredit.
//
//	show=false: drop the markers and the contents (aside) entirely (excluded from the output HTML)
//	show=true : drop only the marker comments and keep the aside body
//
// No-op for old templates that lack the markers.
func stripOrKeepCredit(body []byte, show bool) []byte {
	const startMark = "<!--UNMASK_CREDIT_START-->"
	const endMark = "<!--UNMASK_CREDIT_END-->"
	start := bytes.Index(body, []byte(startMark))
	if start < 0 {
		return body
	}
	end := bytes.Index(body, []byte(endMark))
	if end < 0 || end < start {
		return body
	}
	endPos := end + len(endMark)
	if show {
		// Strip only the marker comments (keep the body).  Delete in end -> start order (avoid index drift).
		body = append(body[:end:end], body[endPos:]...)
		return append(body[:start:start], body[start+len(startMark):]...)
	}
	// Delete markers + body together.  Leftover surrounding whitespace is acceptable.
	return append(body[:start:start], body[endPos:]...)
}

// ServeChallengeOrJSON is the public-facing challenge entry point.  It chooses
// between an HTML challenge (= browser navigation) and a JSON 403 (= XHR /
// fetch / non-HTML API client) so any HTTP method reaches a meaningful
// response instead of Go's ServeMux auto-405.
//
// Pre-v0.1, the route was registered as `GET /unmask/_rl/` / `GET
// /unmask/challenge/`, so a POST / PUT redirect from `limit_req` or
// `$final_challenge` produced a 405 + "Method Not Allowed" with `Allow: GET,
// HEAD`.  Real fetch / XHR clients (= e.g. POST /api/foo from a SPA) saw
// this opaque 405 with no way to recover.  Now: HTML navigation keeps the
// HTML challenge UX, while API clients get a JSON 403 with a challenge_url
// they can redirect the user to.
func (h *Handler) ServeChallengeOrJSON(w http.ResponseWriter, r *http.Request) {
	// A "deny"-mode rate-limit zone is a HARD CAP: over the limit it returns a
	// 403 deny, NOT a challenge.  The native rate-limit hit arrives here as
	// /unmask/_rl<orig URI>; resolve the matched zone from that URI and
	// short-circuit before any challenge render -- otherwise a flooding client
	// (including a _bv holder, whom the deny zone counts via $rate_limit_key_deny)
	// could keep solving CAPTCHAs to buy itself more requests.
	if i := strings.Index(r.URL.Path, "/_rl/"); i >= 0 {
		orig := r.URL.Path[i+len("/_rl"):]
		if orig == "" {
			orig = "/"
		}
		site := siteFromRequest(r, h.snapshotSettings())
		// Any matching deny zone short-circuits: zones now stack (a URI can sit
		// under a challenge zone AND a deny cap at once), and a hard cap must
		// win regardless of which counter nginx tripped first.
		rlDeny := false
		for _, z := range h.cfg().RateLimit.ResolveZonesAll(orig, site) {
			if z.ResolvedChallengeMode() == settings.RateChallengeDeny {
				rlDeny = true
				break
			}
		}
		if rlDeny {
			h.serveRateDeny(w, r, site)
			return
		}
		// An ASN/geo rate rule whose per-rule action is "deny" is also a hard
		// cap over the limit: resolve the client's network and short-circuit to
		// the deny page rather than a recoverable challenge (matching the
		// path-zone deny above).
		if h.netRateOverageAction(adminClientIP(r, *h.cfg()), *h.cfg()) == settings.RateChallengeDeny {
			h.serveRateDeny(w, r, site)
			return
		}
	}
	if isHTMLNavigation(r) {
		h.ServeChallenge(w, r)
		return
	}
	h.serveChallengeJSON(w, r)
}

// isHTMLNavigation reports whether the request is a top-level browser
// navigation that can render an HTML challenge.  Prefers Sec-Fetch-Dest
// (= sent by every modern browser and not by curl / fetch / XHR).  Falls
// back to the Accept header.  Spoofable, so only used to pick the
// failure-response format -- never to grant access.
//
// GET requests without these signals are treated as HTML (= conservative
// default for legacy clients / monitoring probes that still expect the
// classic challenge HTML).
func isHTMLNavigation(r *http.Request) bool {
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		switch dest {
		case "document", "iframe", "frame", "nested-document":
			return true
		default:
			// "empty" (= fetch / XHR), "script", "image", "style", "font",
			// "worker", etc. -- never HTML.
			return false
		}
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode == "cors" || mode == "no-cors" || mode == "websocket" {
		return false
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		return true
	}
	// No Sec-Fetch-* and no text/html in Accept.  Use the method as a final
	// hint: GET / HEAD is most often a browser asking for a page, while
	// POST / PUT / DELETE / PATCH is almost always an API call.
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

// serveChallengeJSON returns a 403 + JSON body to an API client.  Records the
// same event as ServeChallenge (= dashboard sees the challenge fire), so
// operators can tell which paths are blocking real XHR / fetch traffic.
//
// The body shape is small and stable:
//
//	{
//	  "error":         "challenge_required",
//	  "challenge_url": "/unmask/challenge/?_orig=%2Fapi%2Ffoo",
//	  "retry_after":   600,
//	  "reason":        "rate_limit" | "ja4_bot" | "honeypot" | "banned" |
//	                   "protected" | "test" | "none"
//	}
//
// Clients can detect the JSON error and either retry after the
// Retry-After window, redirect the visitor to challenge_url to obtain a
// `_bv` cookie, or surface the reason to the operator.
func (h *Handler) serveChallengeJSON(w http.ResponseWriter, r *http.Request) {
	// Mirror the rate-limit path detection in ServeChallenge so the recorded
	// event carries `rl=1` when this fires off `/unmask/_rl/...`.
	rl := 0
	var rlOrigURI string
	if i := strings.Index(r.URL.Path, "/_rl/"); i >= 0 {
		rl = 1
		rlOrigURI = r.URL.Path[i+len("/_rl"):]
		if rlOrigURI == "" {
			rlOrigURI = "/"
		}
		if r.URL.RawQuery != "" {
			rlOrigURI += "?" + r.URL.RawQuery
		}
	}
	origPath := truncateAt(r.URL.Query().Get("_orig"), 200)
	if origPath == "" {
		origPath = truncateAt(rlOrigURI, 200)
	}
	if origPath == "" {
		origPath = banProbedOrigPath(r, h.basePath()) // native ban-challenge path
	}

	// Reason: mirror ServeChallenge's force-reason ladder so dashboards / API
	// clients see the same axis label that the HTML response would carry.
	action := strings.TrimSpace(r.Header.Get("X-JA4-Action"))
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	// Verdict NAME is unmask-derived from the JA4 (display-only label; not read
	// from the X-JA4-Verdict header) so the recorded name matches forward-auth.
	verdict := h.resolvedVerdictName(ja4)
	if action == "" && ja4 != "" {
		if _, a := matchJA4(ja4, h.cfg().Nginx); a != "" {
			action = a
		}
	}
	reason := "none"
	if action == "bot" {
		reason = "ja4_bot"
	}
	if r.Header.Get("X-Honeypot-Hit") == "1" {
		reason = "honeypot"
	}
	if r.Header.Get("X-Banned") == "1" {
		reason = "banned"
	}
	switch strings.TrimSpace(r.Header.Get("X-Protected-Mode")) {
	case "pow", "captcha", "strict":
		reason = "protected"
	}
	if rl == 1 {
		reason = "rate_limit"
	}

	// challenge_url the client can redirect the user to.  Default-site form;
	// per-site challenges still work because the visit reaches the same
	// handler with `{site}` in the URL anyway.
	chURL := "/unmask/challenge/"
	if origPath != "" {
		chURL += "?_orig=" + url.QueryEscape(origPath)
	}

	// Event recording so the dashboard funnel still counts this as a serve
	// (= distinguishable via payload.non_html_client=1).
	site := siteFromRequest(r, h.snapshotSettings())
	ip := clientIP(r)
	if pkt := events.PackIP(ip); pkt != nil {
		payload := map[string]any{
			"force_reason":    reason,
			"rl":              rl,
			"non_html_client": 1,
			"method":          r.Method,
		}
		// When the BAN hit reason wins, attach the originating BAN row's
		// source so the dashboard can split community_bans vs honeypot vs
		// manual without a nginx-side config change (= BanMgr already
		// knows which source put the row in the map).
		if reason == "banned" && h.BanMgr != nil {
			if src, ok := h.BanMgr.IsBannedSource(r.Context(), ip, ja4); ok && src != "" {
				payload["ban_source"] = src
			}
		}
		if origPath != "" {
			payload["orig_path"] = origPath
		}
		events.InsertAsync(h.DB, &events.Event{
			Site:         site,
			Host:         h.HostID,
			Scheme:       schemeFromRequest(r),
			Port:         portFromRequest(r),
			IPPacked:     pkt,
			UserAgent:    r.Header.Get("User-Agent"),
			JA4:          safeJA4(ja4),
			JA4Verdict:   verdict,
			JA4VerdictID: h.VerdictNameToID(verdict),
			Phase:        string(events.PhaseServe),
			Payload:      payload,
		})
	}

	// Same response headers as the HTML challenge so reverse-proxy logs /
	// CDN policies treat both responses identically.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Retry-After", "600")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":         "challenge_required",
		"challenge_url": chURL,
		"retry_after":   600,
		"reason":        reason,
	})

	h.Notifier.ChallengeServed()
}

// serveRateDeny writes the hard-cap response for a "deny"-mode rate-limit zone.
// Unlike a challenge serve it offers NO escape hatch (no PoW / CAPTCHA): the
// limit already counts _bv holders, so handing out a fresh challenge would just
// sell more requests.  Browsers get the tiny self-contained page above; API
// clients get a stable JSON body.  Both are 403.  A serve event is recorded
// (payload.deny=1) so the dashboard funnel still counts the block.
func (h *Handler) serveRateDeny(w http.ResponseWriter, r *http.Request, site string) {
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	verdict := h.resolvedVerdictName(ja4) // unmask-derived (not the X-JA4-Verdict header)
	// ref: support correlation id shown on the deny page + stored on the event,
	// so a wrongly-blocked visitor's report resolves to this exact hit.
	ref := newRef()
	if pkt := events.PackIP(clientIP(r)); pkt != nil {
		events.InsertAsync(h.DB, &events.Event{
			Site:         site,
			Host:         h.HostID,
			Scheme:       schemeFromRequest(r),
			Port:         portFromRequest(r),
			IPPacked:     pkt,
			UserAgent:    r.Header.Get("User-Agent"),
			JA4:          safeJA4(ja4),
			JA4Verdict:   verdict,
			JA4VerdictID: h.VerdictNameToID(verdict),
			Phase:        string(events.PhaseServe),
			Payload: map[string]any{
				"force_reason": "rate_limit",
				"rl":           1,
				"deny":         1,
				"method":       r.Method,
				"ref":          ref,
			},
		})
	}

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Retry-After", "600")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if !isHTMLNavigation(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "rate_limited",
			"reason":      "rate_limit",
			"retry_after": 600,
		})
		return
	}
	cfg := h.cfg()
	br := cfg.Branding.Resolve(site)
	preset := br.ResolvedDenyRateCopyPreset()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(renderRateDenyC(br, preset, br.ResolvedDenyRateTheme(), r.Header.Get("Accept-Language"), h.basePath(), ref, denyColorsRate(br)))
}

// ServeBanDeny writes the "blocked" page for a ban whose action is "deny".
// nginx rewrites a ban-deny hit to /unmask/_ban<orig URI> (the native plugin
// detects the ban without the daemon; only this page needs it, and nginx fails
// closed -- a daemon-down request lands in @unmask_daemon_down with no saved
// original and returns 503, never a free pass).  Like the rate-limit deny there
// is no escape hatch, but a ban is persistent until the operator lifts it, so
// the copy is "blocked" with no Retry-After / "try again" framing.
func (h *Handler) ServeBanDeny(w http.ResponseWriter, r *http.Request) {
	site := siteFromRequest(r, h.snapshotSettings())
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	verdict := h.resolvedVerdictName(ja4) // unmask-derived (not the X-JA4-Verdict header)
	// ref: support correlation id shown on the ban page + stored on the event.
	ref := newRef()
	// The URL the banned client hit is preserved in the path: nginx rewrites a
	// deny-ban to /unmask/_ban<orig URI>, so strip that prefix back off and record
	// it (display only -- this page never redirects) so the hunt log shows WHAT
	// the client was probing instead of a blank URL column.
	origPath := ""
	if p := r.URL.RequestURI(); strings.HasPrefix(p, h.basePath()+"/_ban") {
		origPath = truncateAt(strings.TrimPrefix(p, h.basePath()+"/_ban"), 200)
	}
	if pkt := events.PackIP(clientIP(r)); pkt != nil {
		events.InsertAsync(h.DB, &events.Event{
			Site:         site,
			Host:         h.HostID,
			Scheme:       schemeFromRequest(r),
			Port:         portFromRequest(r),
			IPPacked:     pkt,
			UserAgent:    r.Header.Get("User-Agent"),
			JA4:          safeJA4(ja4),
			JA4Verdict:   verdict,
			JA4VerdictID: h.VerdictNameToID(verdict),
			Phase:        string(events.PhaseServe),
			Payload: map[string]any{
				"force_reason": "banned",
				"deny":         1,
				"ban":          1,
				"method":       r.Method,
				"ref":          ref,
				"orig_path":    origPath,
			},
		})
	}

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if !isHTMLNavigation(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  "blocked",
			"reason": "banned",
		})
		return
	}
	cfg := h.cfg()
	br := cfg.Branding.Resolve(site)
	banPreset := br.ResolvedDenyBanCopyPreset()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(renderBanDenyC(br, banPreset, br.ResolvedDenyBanTheme(), r.Header.Get("Accept-Language"), h.basePath(), ref, denyColorsBan(br)))
}

// axisDenyReason re-derives WHICH axis denied this request, for the event
// label.  nginx made the decision from the rendered maps and dispatches here
// without carrying the reason, so "a rule said no" was all the hunt log could
// show -- true, and useless to the operator asking WHICH rule, on a page whose
// whole job is answering that.
//
// The daemon asks the same resolvers in the same order server.inc composes
// them ($unmask_axis_deny: country, then ASN, then UA, then JA4 verdict, then
// the community feed), so the label matches the decision that was actually
// made.  This is a label, never a decision: the block already happened, and an
// answer this cannot derive falls back to the generic name rather than
// guessing.
func (h *Handler) axisDenyReason(r *http.Request, ja4, verdict string) (reason, rule string) {
	cfg := *h.cfg()
	if h.IPGeo != nil {
		if ip := adminClientIP(r, cfg); ip != "" {
			info := h.IPGeo.LookupInfo(ip)
			if h.IPGeo.Loaded() {
				cc := strings.ToUpper(strings.TrimSpace(info.Country))
				if d, _, ok := geoDecideForCountry(cc, cfg.Nginx.Geo); ok && d.sev == sevDeny {
					return "geo_deny", cc
				}
			}
			if h.IPGeo.ASNLoaded() {
				if d, netKey, _, ok := asnResolve(info.ASN, info.ASNOrg, cfg.Nginx.Asn); ok && d.sev == sevDeny {
					return "asn_deny", strings.TrimPrefix(netKey, "asn:")
				}
			}
		}
	}
	if ua := r.Header.Get("User-Agent"); ua != "" && hardDenyUA(ua, cfg.Nginx) {
		return "ua_deny", ""
	}
	if nginxconf.ResolveJA4VerdictAction(verdict, cfg.Nginx) == settings.RateChallengeDeny {
		return "ja4_deny", verdict
	}
	if m := h.communityBansMatcher(); m != nil {
		if d, ok := communityBansDecide(m, adminClientIP(r, cfg), ja4, cfg); ok && d.sev == sevDeny {
			return "community_deny", strings.TrimPrefix(d.reason, "community_bans:")
		}
	}
	return "axis_deny", ""
}

// ServeAxisDeny writes the "blocked" page for a request an axis resolved to
// "deny" -- a UA black-list row pinned to deny, a country rule, an ASN rule.
//
// It exists because "deny" did not deny.  Every axis below the pass cookie was
// only consulted when $bv_any_valid was 0, so the word meant "deny unless this
// client already cleared a challenge once".  Against anything that can mint a
// cookie that is not a block at all: on a production install, Bytespider
// solved the proof-of-work across a large address pool and then served itself
// freely for a day through a UA the operator had already taken out of the
// rescue list.  Raising the PoW difficulty cannot reach it either -- a
// cookie lasts a week, so the cost is one solve per address per week no matter
// what the difficulty is.  The only fix is ordering.
//
// So this is dispatched from server.inc alongside the ban, BEFORE anything
// looks at _bv, and it deliberately shares the ban's shape: same branded page,
// same JSON form for non-navigations, no escape hatch.  A ban is the one axis
// that always worked this way; this makes the rest of them mean it too.
func (h *Handler) ServeAxisDeny(w http.ResponseWriter, r *http.Request) {
	site := siteFromRequest(r, h.snapshotSettings())
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	verdict := h.resolvedVerdictName(ja4)
	ref := newRef()
	origPath := ""
	if p := r.URL.RequestURI(); strings.HasPrefix(p, h.basePath()+"/_deny") {
		origPath = truncateAt(strings.TrimPrefix(p, h.basePath()+"/_deny"), 200)
	}
	denyReason, denyRule := h.axisDenyReason(r, ja4, verdict)
	if pkt := events.PackIP(clientIP(r)); pkt != nil {
		payload := map[string]any{
			// Named for the axis that fired, not folded into "banned": the hunt
			// log has to separate "a rule the operator wrote said no" from "a
			// signal fired and banned this client", or the one row that explains
			// a support ticket is the one that reads wrong.  And it names WHICH
			// axis, because "some rule" sends the operator back to reading
			// config to find out which.
			"force_reason": denyReason,
			"deny":         1,
			"method":       r.Method,
			"ref":          ref,
			"orig_path":    origPath,
		}
		// deny_rule: the specific entry that matched (AS number, country code,
		// verdict name).  Which rule, not just which axis -- an operator running
		// a dozen ASN rules needs the one that fired.
		if denyRule != "" {
			payload["deny_rule"] = denyRule
		}
		events.InsertAsync(h.DB, &events.Event{
			Site:         site,
			Host:         h.HostID,
			Scheme:       schemeFromRequest(r),
			Port:         portFromRequest(r),
			IPPacked:     pkt,
			UserAgent:    r.Header.Get("User-Agent"),
			JA4:          safeJA4(ja4),
			JA4Verdict:   verdict,
			JA4VerdictID: h.VerdictNameToID(verdict),
			Phase:        string(events.PhaseServe),
			Payload:      payload,
		})
	}

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if !isHTMLNavigation(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  "blocked",
			"reason": denyReason,
		})
		return
	}
	cfg := h.cfg()
	br := cfg.Branding.Resolve(site)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	// The ban copy, because to the visitor this IS a block: persistent until the
	// operator changes the rule, with no retry that would help.  The rate-limit
	// wording ("try again shortly") would be a lie here.
	_, _ = w.Write(renderBanDenyC(br, br.ResolvedDenyBanCopyPreset(),
		br.ResolvedDenyBanTheme(), r.Header.Get("Accept-Language"), h.basePath(), ref, denyColorsBan(br)))
}

// banProbedOrigPath recovers the URL a banned client was probing when the
// native ban-challenge rewrite dropped the _orig arg.  server.inc rewrites a
// banned IP from its probed URI straight to /unmask/challenge/ (no _orig) so a
// daemon-down replay can't use a saved original to slip past the ban; but nginx
// still forwards the untouched request line as X-Original-URI (= $request_uri,
// which it sets + anti-spoofs), so the probed URL survives there.  Honor it only
// when it is a real off-basePath path: a DIRECT challenge request carries
// /unmask/challenge/... in this header (the reason a blanket fallback was once
// dropped), which the guard rejects.  Display-only; the ban keeps enforcing
// per-request while the daemon is up.  Empty when there is nothing safe to use.
// protectedOrigURI recovers the URI a challenge is being served FOR, so the
// serve can resolve the same protected-path rule the forward-auth check just
// enforced.
//
// It deliberately does NOT apply banProbedOrigPath's off-basePath guard.  That
// guard exists so a direct hit on the challenge cannot masquerade as a probed
// URL, but reusing it here dropped exactly the path the shipped "unmask itself"
// preset is for: /unmask/admin/.  The two halves of one decision then
// disagreed -- the check resolved the rule and demanded a CAPTCHA-grade pass
// for a captcha-ending mode, while the serve, blind to the URI, handed out
// whatever the UA axis picked (a PoW-only screen on a stock install).  The
// visitor solved it, was refused for holding the wrong grade, and was
// challenged again, forever.  Observed on a production forward-auth node:
// 103 serve/check pairs in 30 minutes for one operator trying to reach
// their own admin.
//
// The unmask mount itself is still excluded -- a direct request to the
// challenge / api / static endpoints must not resolve to a rule about itself
// -- but everything under it that a preset or a custom row can name is kept.
func protectedOrigURI(r *http.Request, basePath string) string {
	oru := strings.TrimSpace(r.Header.Get("X-Original-URI"))
	if !strings.HasPrefix(oru, "/") {
		return ""
	}
	// The endpoints the forward-auth conf leaves auth_request off: they can
	// never be the protected URI, and a direct hit carries them here.
	for _, self := range []string{"/challenge/", "/challenge.html", "/api/", "/static/", "/_deny"} {
		if strings.HasPrefix(oru, basePath+self) {
			return ""
		}
	}
	return truncateAt(oru, 200)
}

func banProbedOrigPath(r *http.Request, basePath string) string {
	oru := strings.TrimSpace(r.Header.Get("X-Original-URI"))
	if strings.HasPrefix(oru, "/") && !strings.HasPrefix(oru, basePath+"/") {
		return truncateAt(oru, 200)
	}
	return ""
}

// protectedModeForOrig resolves the protected-path mode ("pow" / "captcha" /
// "pow_then_captcha") for the original URI a challenge is being served for,
// scanning the enabled preset groups (honoring a preset-level mode override)
// and then the per-site custom rows the same way the rendered $protected_mode
// map does (case-insensitive, first match wins).  Returns "" when the URI hits
// no protected rule.  Used on the forward-auth axis (a plain proxy with no
// nginx maps): both to serve the right chain and to enforce the CAPTCHA grade.
func protectedModeForOrig(n settings.Nginx, site, orig string) string {
	if orig == "" {
		return ""
	}
	if i := strings.IndexByte(orig, '?'); i >= 0 {
		orig = orig[:i]
	}
	// Same resolver the render uses, so a blank mode cannot become one thing in
	// the nginx map and another in the served challenge / grade requirement.
	modeOr := func(m string) string {
		return nginxconf.ResolveProtectedMode(m, n.ProtectedPaths)
	}
	enabled := make(map[string]bool, len(n.ProtectedPaths.EnabledPresets))
	for _, id := range n.ProtectedPaths.EnabledPresets {
		enabled[id] = true
	}
	for _, g := range nginxconf.ProtectedPathPresetGroups {
		if !enabled[g.ID] {
			continue
		}
		// A preset-level override replaces the rule's own mode (matches
		// EffectiveProtectedPathRules so both wires agree).
		override := ""
		if m, ok := n.ProtectedPaths.PresetMode[g.ID]; ok && nginxconf.IsValidProtectedMode(m) {
			override = m
		}
		for _, rule := range g.Rules {
			if re := compileCachedRe("(?i)" + rule.Pattern); re != nil && re.MatchString(orig) {
				if override != "" {
					return override
				}
				return modeOr(rule.Mode)
			}
		}
	}
	for _, row := range n.ProtectedPaths.ResolvePaths(site) {
		if row.Disabled {
			continue
		}
		if re := compileCachedRe("(?i)" + row.Path); re != nil && re.MatchString(orig) {
			return modeOr(row.Mode)
		}
	}
	return ""
}

// ServeChallenge: GET {base}/challenge/
//
// Rate-limit path: nginx rewrites a 429 into /unmask/_rl<orig URI> (see
// server.inc @unmask_rate_challenge).  ServeChallengeOrJSON routes the HTML
// form here, where the "/_rl/" prefix is detected, the original URI restored,
// and the request treated as rl=1.
func (h *Handler) ServeChallenge(w http.ResponseWriter, r *http.Request) {
	site := siteFromRequest(r, h.snapshotSettings())
	// Explicit operator-side force (= /test/force-pow / /admin/test/force-*
	// add ?_force=...) -- short-circuit the monitor / passthrough early exits
	// below so the operator can preview the challenge page even when the
	// site is in observe-only or passthrough mode.  Public /test/* is already
	// gated by Challenge.PublicTestPages; /admin/test/* is auth-gated.
	forceQuery := strings.TrimSpace(r.URL.Query().Get("_force"))
	// monitor mode: don't serve a challenge, redirect immediately.  Keep the
	// event with phase=serve (preserves dashboard aggregation continuity).
	// In forward-auth mode AuthCheck has already returned pass, so this path
	// is not reached.  Reached via native mode (nginx plugin sends straight
	// to the challenge route).
	if forceQuery == "" && h.snapshotSettings().Challenge.Resolve(site).IsObserveOnly() {
		h.serveObserveOnlyRedirect(w, r, site)
		return
	}
	action := strings.TrimSpace(r.Header.Get("X-JA4-Action"))
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	// Verdict NAME is unmask-derived from the JA4 (X-Client-JA4 = nginx's
	// $effective_ja4), not read from the X-JA4-Verdict header: the name is a
	// display-only label unmask owns, and deriving it keeps native + forward-auth
	// identical (a clean JA4 -> "" -> rendered "ok" at display time).
	verdict := h.resolvedVerdictName(ja4)
	// Even without the X-JA4-Action header (nginx configs that don't pass it,
	// such as GCP LB / legacy snippets), bot detection should still work —
	// re-derive the action from settings (the Action enum of preset / extra
	// rules is the source of truth).
	if action == "" && ja4 != "" {
		if _, a := matchJA4(ja4, h.cfg().Nginx); a != "" {
			action = a
		}
	}
	// forceReason: why CAPTCHA is forced (challenge JS uses this for the PoW-skip decision).
	//
	//	"none"       : normal PoW (no force)
	//	"ja4_bot"    : JA4 verdict action=bot
	//	"honeypot"   : honeypot hit (trap matched)
	//	"banned"     : persistent BAN list hit
	//	"protected"  : mode coming from protected path (captcha / strict)
	//	"rate_limit" : rate-limit redirect (/_rl/...)
	//	"ua_target"  : the UA matched the black list (ua-filter tab).  Resolved
	//	               here rather than forwarded: native nginx fires this
	//	               challenge off $is_challenge_target and sends no header.
	//	"test"       : debug paths `?_test_ja4=1` / `?_force=captcha`
	//
	// Priority is determined by overwrite order (last writer wins).
	// rate_limit / test are placed later than others to reliably override
	// debug / RL-via paths.
	forceReason := "none"
	// The chain the network axis resolved, kept from the same lookup that
	// named the axis so the two cannot disagree.  Empty unless a geo / ASN
	// rule matched.
	netChMode := ""
	if action == "bot" {
		forceReason = "ja4_bot"
	}
	if r.Header.Get("X-Honeypot-Hit") == "1" {
		forceReason = "honeypot"
	}
	if r.Header.Get("X-Banned") == "1" {
		forceReason = "banned"
	}
	ppMode := ""
	switch m := strings.TrimSpace(r.Header.Get("X-Protected-Mode")); m {
	case nginxconf.ProtectedModePoW, nginxconf.ProtectedModeCaptcha, nginxconf.ProtectedModePoWThenCaptcha:
		forceReason = "protected"
		ppMode = m
	}
	// The forward-auth axis serves the challenge through a plain proxy -- no
	// nginx $protected_mode map, so no X-Protected-Mode header.  Resolve the
	// protected rule (and its per-path mode) from the URI the visitor
	// originally tried: the _orig query (apache mode's lua redirect), else
	// X-Original-URI (fa-nginx's internal rewrite keeps $request_uri = the
	// protected URI).  Gated on forceReason=="none" so a honeypot / ban / JA4
	// escalation keeps its own screen.
	if ppMode == "" && forceReason == "none" {
		orig := r.URL.Query().Get("_orig")
		if orig == "" {
			orig = protectedOrigURI(r, h.basePath())
		}
		if m := protectedModeForOrig(h.cfg().Nginx,
			siteFromRequest(r, h.snapshotSettings()), orig); m != "" {
			forceReason = "protected"
			ppMode = m
		}
	}
	// Community feed hit.  Native nginx decides only THAT this request is
	// challenged (its map lookup has no way to say why); the daemon holds the
	// same map files in memory, so the reason and the chain are resolved here
	// from the same bytes nginx matched on.  Before this, a feed hit reached
	// the visitor as force_reason="none" on an unremarkable default chain: the
	// operator could not tell a shared-list hit from ordinary traffic, and on
	// an install whose default chain is pow_only the visitor solved a PoW that
	// the CAPTCHA-grade requirement then refused, re-challenging forever.
	//
	// Listed after protected so a feed hit is the story when both apply: it is
	// the rarer and more actionable signal.  A deny action never arrives here
	// (nginx / auth_check block the request outright), so this only ever picks
	// a challenge chain.
	cbHitKind := ""
	if h.CommunityBans != nil && h.cfg().CommunityBans.ApplyActive() {
		if kind, ok := h.CommunityBans.Matcher().Hit(clientIP(r), ja4); ok {
			cbHitKind = kind
			forceReason = "community_bans"
		}
	}

	// Rate-limit path detection: "/_rl/" prefix in URL.Path -> rl=1.
	// Reconstruct the original URI from the path remainder + RawQuery
	// (concatenated to match the nginx split).
	rl := "0"
	var rlOrigURI string
	if i := strings.Index(r.URL.Path, "/_rl/"); i >= 0 {
		rl = "1"
		forceReason = "rate_limit"
		// The remainder after /_rl is the original path. (e.g. "/unmask/_rl/foo" -> "/foo")
		rlOrigURI = r.URL.Path[i+len("/_rl"):]
		if rlOrigURI == "" {
			rlOrigURI = "/"
		}
		if r.URL.RawQuery != "" {
			rlOrigURI += "?" + r.URL.RawQuery
		}
	}

	test := "0"
	if r.URL.Query().Get("_test_ja4") == "1" {
		test = "1"
		forceReason = "test"
	}

	// _force= debug override (via /unmask/force-pow / /unmask/force-captcha /
	// /unmask/force-pow-then-captcha).
	//   "pow"              : forceReason="none" + chMode=pow_only.  PoW only path.
	//   "captcha"          : forceReason="test" + chMode=captcha_only.  CAPTCHA only.
	//   "pow_then_captcha" : forceReason="none" + chMode=pow_then_captcha.  Full chain.
	switch strings.TrimSpace(r.URL.Query().Get("_force")) {
	case "pow":
		forceReason = "none"
		test = "1"
	case "captcha":
		forceReason = "test"
		test = "1"
	case "pow_then_captcha":
		forceReason = "none"
		test = "1"
	}

	// The UA black list is the one axis nginx cannot name for itself: it fires
	// the challenge off $is_challenge_target and forwards no header saying so,
	// which left the operator's own rule recorded as force_reason=none -- the
	// hunt log showed the rule working and could not say a rule was involved.
	// Resolved once here (the scan walks every preset pattern) and reused for
	// the chain further down.  Placed after the other reasons so honeypot /
	// ban / protected / rate-limit / test keep theirs.
	uaTargetCat, uaRowAction := "", ""
	if ua := r.Header.Get("User-Agent"); ua != "" {
		_, uaTargetCat, uaRowAction = lookupUAListed(ua, h.cfg().Nginx)
	}
	// uaListed is what "ua_target" MEANS: this visitor's UA matched a
	// black-list pattern (preset or extra row).  Both the attribution and the
	// black-list chain key on this one fact; a serve nothing here matched is
	// the Global axis's business (bucket actions), not this list's.
	uaListed := uaTargetCat == "challenge"

	// isPreview: the operator's theme-tab iframe (?_preview=1) or an
	// auth-gated /admin/test/ page.  Must serve the real challenge markup, not
	// a redirect -- the operator is inspecting the page, not passing it.
	isPreview := strings.Contains(r.URL.Path, "/admin/test/") || strings.TrimSpace(r.URL.Query().Get("_preview")) == "1"

	// Silent roaming rebind: a client that already solved (valid _bvj) and
	// merely changed IP gets its _bv re-bound and bounced back instead of a
	// PoW.  Plain path only -- every forced reason (ja4_bot / honeypot /
	// banned / protected / rate-limit) and every test/preview path keeps
	// serving the real challenge.  Without the preview guard, an operator whose
	// browser already holds a valid _bv sees the theme preview redirect to the
	// site instead of rendering the challenge.  Placed before the serve event
	// fires so a rebind never counts as a challenge serve (it isn't one, and
	// inflating serves/IP here would feed the over-block breaker false positives).
	// Session token for every event this request writes.  Minted BEFORE the
	// rebind attempt so a refusal and the challenge it falls through to share
	// one session in the hunt log: they are the same request, and the operator
	// reading "why did this roaming client get a PoW" needs the refusal reason
	// and the serve on one row.  Before this, the reject row carried no token
	// and sat alone, indistinguishable from an unrelated event.  A rebind that
	// succeeds serves no challenge page, so its token is simply never echoed.
	beaconToken := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase, clientIP(r))
	if forceReason == "none" && rl == "0" && test == "0" && forceQuery == "" && !isPreview {
		if h.tryRebind(w, r, site, beaconToken) {
			return
		}
	}

	// Attribute a serve that no coarser signal claimed to the UA / network axes
	// (header-integrity, stale-browser, ASN / country), so it lands in the
	// CAPTCHA-force breakdown instead of folding into "none".  Gated on
	// forceReason=="none" so a stronger reason (ja4_bot / honeypot / banned /
	// protected / rate_limit) keeps its attribution; among these, header wins
	// over stale wins over the network axis (most-specific first).  Placed
	// AFTER the rebind gate (so a roamed _bv holder is still re-bound silently,
	// not re-challenged) and BEFORE the __CAPTCHA_FORCE__ marker below carries
	// force_reason into the page.
	if forceReason == "none" {
		g := h.cfg().Global
		if headerAxisFiresForServe(r, g) {
			forceReason = "header"
		}
		if forceReason == "none" && staleBrowserFiresForServe(r, g) {
			forceReason = "stale"
		}
		if forceReason == "none" {
			if reason, act := h.netChallengeReason(adminClientIP(r, *h.cfg()), *h.cfg()); reason != "" {
				forceReason = reason
				netChMode = act
			}
		}
		// The operator's own UA rule, last: nginx fires this challenge off
		// $is_challenge_target and forwards no header, so without it the rule
		// shows up as "none".  Lowest priority of the page-side axes, and
		// deliberately here rather than earlier -- the rebind gate above reads
		// "no forced reason", so naming the axis sooner re-challenged a visitor
		// who had merely changed IP.  A serve no pattern matched stays "none":
		// the Global axis challenging by default is the site's posture, not a
		// rule hit.
		if forceReason == "none" && uaListed {
			forceReason = "ua_target"
		}
	}

	body, err := h.loadChallengeHTML()
	if err != nil {
		log.Printf("challenge.html load failed: %v", err)
		http.Error(w, "challenge unavailable", http.StatusInternalServerError)
		return
	}
	body = bytes.ReplaceAll(body, []byte(challengePlaceholder),
		[]byte(`/*__CAPTCHA_FORCE__*/"`+forceReason+`"`))
	body = bytes.ReplaceAll(body, []byte(challengeProbe),
		[]byte("<!--probe=ON force_reason="+forceReason+"-->"))
	// Resolve per-site challenge + branding once; reuse for every placeholder
	// substitution below.  Default verbatim when the site has no Sites entry.
	// Authorized test-page preview may resolve the challenge + branding VALUES
	// for another site via the site-scoped route (/test/site/{site}/), while
	// events / cookies / PoW seed stay bound to the physical request host --
	// see testSiteOverride for who is allowed.
	cfgSite := site
	if o, ok := h.testSiteOverride(r); ok {
		cfgSite = o
	}
	ch := h.cfg().Challenge.Resolve(cfgSite)
	br := h.cfg().Branding.Resolve(cfgSite)
	body = bytes.ReplaceAll(body, []byte(captchaPlaceholder),
		[]byte("/*__CAPTCHA__*/"+captchaInjectJSON(ch.CaptchaProvider)))
	theme := pickChallengeTheme(r, br.Theme)
	body = bytes.ReplaceAll(body, []byte(themePlaceholder),
		[]byte(`/*__THEME__*/"`+theme+`"`))
	// Per-theme color override (recolor the active theme to the site's palette).
	// "auto" resolves its palette client-side, so emit both the default (light)
	// and dark entries and let the inline bootstrap pick; any other theme emits
	// its own pair.  Operator preview (_preview=1) can substitute the active
	// theme's colors via query params so the theme-tab iframes reflect unsaved
	// edits live.
	customJSON, customAutoJSON := []byte("null"), []byte("null")
	if theme == "auto" {
		obj := map[string]any{}
		if bg, text := br.CustomColorsFor("light"); bg != "" {
			obj["light"] = map[string]string{"bg": bg, "text": text}
		}
		if bg, text := br.CustomColorsFor("dark"); bg != "" {
			obj["dark"] = map[string]string{"bg": bg, "text": text}
		}
		if len(obj) > 0 {
			customAutoJSON, _ = json.Marshal(obj)
		}
	} else {
		bg, text := br.CustomColorsFor(theme)
		if isPreview {
			if pb, pt := r.URL.Query().Get("_preview_custom_bg"), r.URL.Query().Get("_preview_custom_text"); settings.IsValidHexColor(pb) && settings.IsValidHexColor(pt) {
				bg, text = pb, pt
			}
		}
		if bg != "" {
			customJSON, _ = json.Marshal(map[string]string{"bg": bg, "text": text})
		}
	}
	body = bytes.ReplaceAll(body, []byte(customColorsPlaceholder),
		append([]byte("/*__CUSTOM__*/"), customJSON...))
	body = bytes.ReplaceAll(body, []byte(customAutoColorsPlaceholder),
		append([]byte("/*__CUSTOM_AUTO__*/"), customAutoJSON...))
	// Live-preview logo override (settings "Page design" tab): the operator
	// picked a logo that isn't saved yet, uploaded it to the ephemeral preview
	// store, and the iframe carries its token.  Point the brand JSON at the
	// preview URL so the picked image shows immediately.  Preview-gated + token
	// shape-checked, same posture as the custom-color override above.
	logoOverride := ""
	suppressLogo := false
	if isPreview {
		switch raw := strings.TrimSpace(r.URL.Query().Get("_preview_logo")); {
		case raw == "none": // operator clicked remove but hasn't saved yet
			suppressLogo = true
		case isPreviewLogoToken(raw):
			logoOverride = h.previewLogoURL(raw)
		}
	}
	// A site preview points the logo at the site-scoped serve route so it
	// fetches the previewed site's logo, not the request host's.
	logoSite := ""
	if cfgSite != site {
		logoSite = cfgSite
	}
	body = bytes.ReplaceAll(body, []byte(brandingPlaceholder),
		[]byte("/*__BRANDING__*/"+brandingInjectJSON(br, h.basePath(), logoOverride, suppressLogo, logoSite)))
	// Inline challenge.js into the page instead of loading it as an external
	// <script src>.  A client that fails to fetch the 53KB external file (an
	// extension, a flaky network, an odd proxy) renders the challenge but never
	// runs the PoW, so it re-challenges forever -- the widespread tool1-jp loop
	// where the JS-load count was a fraction of the serve count.  Inlining
	// removes the external fetch entirely.  Escape any "</script>" in the JS so
	// it can't terminate the inline block early; fall back to the external tag
	// if the JS can't be read.
	if js, jerr := h.loadChallengeJS(); jerr == nil && len(js) > 0 {
		js = bytes.ReplaceAll(js, []byte("</script"), []byte(`<\/script`))
		inlined := make([]byte, 0, len(js)+len("<script></script>"))
		inlined = append(inlined, []byte("<script>")...)
		inlined = append(inlined, js...)
		inlined = append(inlined, []byte("</script>")...)
		body = bytes.Replace(body, []byte(challengeJSScriptTag), inlined, 1)
	}
	// Cache-bust the (fallback) external challenge.js URL with the admin's
	// start-time epoch.  No-op once the tag above has been inlined.
	body = bytes.ReplaceAll(body, []byte(buildVPlaceholder),
		[]byte(strconv.FormatInt(buildVersionStamp, 10)))

	// challenge_mode resolution:
	//   1) rate-limit path (= "/_rl/" / forceReason="rate_limit") uses
	//      rate_limit.default.challenge_mode.
	//   2) every other path (= ja4_bot / honeypot / banned / protected /
	//      UA-blacklist match) uses challenge_targets.default_action, with a
	//      fall-back to the rate-limit default so existing installs that
	//      don't yet have default_action set continue to behave as before.
	//   3) ?chm= explicit override from the auth_request wrapper.
	//   4) ?_force= debug override (via /unmask/force-pow / -captcha).
	// Monitoring mode (= let every request through).  When ON -- either the
	// operator's Global.Passthrough, or the over-block circuit breaker tripping
	// into auto-passthrough -- we short-circuit the challenge: issue a signed _bv
	// and bounce the visitor to the original URL without showing PoW / CAPTCHA.
	if forceQuery == "" && (h.cfg().Global.Passthrough || h.overBlockPassthrough()) {
		// Issue a PROPERLY-SIGNED _bv so the visitor doesn't loop back through
		// nginx's challenge redirect.  This MUST be a real HMAC-signed cookie
		// (IssueValue, same as the post-PoW / CAPTCHA success path): the native C
		// plugin verifies the signature and rejects an unsigned sentinel, so the
		// old "passthrough.0.c" placeholder re-challenged forever in native mode
		// (passthrough silently never recovered).  Bind it to the same client IP
		// + host the plugin folds into its HMAC, so the cookie verifies.  Skipped
		// when ?_force= is set so the operator's test endpoint can still preview
		// the page in passthrough mode.
		// Minted as its own kind, not as a CAPTCHA.  Nobody proved anything
		// for this cookie -- enforcement was suspended -- and calling it a
		// CAPTCHA pass outlives the suspension: on one install a 20-minute
		// monitoring window handed out cookies that stayed valid, and
		// CAPTCHA-graded, for a fortnight.  A rule that requires a real
		// CAPTCHA must not be satisfied by the moment enforcement was off.
		val := cookies.IssueValue(h.cfg().Secret.BVSecret, clientIP(r), requestHost(r), "passthrough")
		h.setBVCookie(w, r, val)
		target := "/"
		if rlOrigURI != "" {
			target = rlOrigURI
		} else if orig := strings.TrimSpace(r.URL.Query().Get("orig")); isLocalRedirect(orig) {
			target = orig
		}
		if !isLocalRedirect(target) {
			target = "/" // never emit a client-supplied off-site Location
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	chMode := h.cfg().RateLimit.Default.ResolvedChallengeMode()
	if forceReason == "none" {
		// "no-match" path: split the chain by whether the UA looks like
		// a real browser.  Empty (= fresh install, never touched the
		// Operating mode tab) means "strict" — the default protection posture.
		ua := r.Header.Get("User-Agent")
		var pick string
		if classify.IsKnownBrowser(ua) {
			pick = h.cfg().Global.KnownBrowserAction
		} else {
			pick = h.cfg().Global.UnknownUAAction
		}
		if pick == "" {
			pick = "pow_only" // strict default
		}
		if pick != "pass" && settings.IsValidRateChallengeMode(pick) {
			chMode = pick
		}
	}
	if forceReason == "protected" {
		// Mode == action: the per-path mode maps 1:1 to the served chain
		//   pow -> PoW only; captcha -> straight CAPTCHA; pow_then_captcha -> chain.
		// No default-action / rate-limit-linkage override on top (removed in the
		// redesign) -- the mode the operator picked is exactly what gets served.
		chMode = nginxconf.ChModeForProtectedMode(ppMode)
	} else if forceReason == "asn" || forceReason == "geo" {
		// The matched rule's own action, the way honeypot and ja4_bot already
		// serve theirs.  Without this branch the network axis was attributed
		// and then handed the default chain: a rule saying captcha_only was
		// served as pow_then_captcha, because the grade backstop below saw a
		// chain that did not end in a CAPTCHA and escalated it -- which keeps
		// the proof-of-work leg on purpose, and the proof-of-work leg is
		// precisely what an operator picking captcha_only is declining to
		// offer a network whose clients run JavaScript.
		if settings.IsValidRateChallengeMode(netChMode) {
			chMode = netChMode
		}
	} else if forceReason == "honeypot" {
		// The trap's own action (its row, or its preset group), then the tab
		// default -- the same order forward-auth's honeypotDecide resolves, via
		// the same resolver.  This branch used to read only the tab default, so
		// a trap row pinned to captcha_only or deny was honoured behind a load
		// balancer and ignored on native: the per-row picker was decorative on
		// one wire, which is the shape the protected-path redesign removed.
		if act := strings.TrimSpace(h.cfg().Nginx.Honeypot.DefaultAction); act != "" && settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
		// The trapped URI reaches the serve the same way the protected axis
		// resolves its path: the _orig query (apache's lua redirect), else the
		// URI the native rewrite preserved.
		hpURI := strings.TrimSpace(r.URL.Query().Get("_orig"))
		if hpURI == "" {
			hpURI = banProbedOrigPath(r, h.basePath())
		}
		if act, matched := nginxconf.ResolveHoneypotAction(hpURI,
			siteFromRequest(r, h.snapshotSettings()), h.cfg().Nginx); matched &&
			settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
	} else if forceReason == "rate_limit" {
		// Native rate zones carry only "you hit a zone", not which ASN/geo rule
		// -- re-derive the client's network from the IP and, if it matches a
		// rate-mode rule, serve that rule's per-rule action instead of the base
		// default (the plumbing this branch used to lack).  A path-zone deny was
		// already short-circuited to serveRateDeny upstream, so only ASN/geo
		// per-rule actions land here; "" (no network rule) leaves chMode alone.
		if act := h.netRateOverageAction(adminClientIP(r, *h.cfg()), *h.cfg()); act != "" && settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
	} else if forceReason == "ja4_bot" {
		// EffectiveJA4BotChain, not the raw resolver: the same effective
		// chain ja4Decide answers checks with and the grade gate demands.
		// Serving anything else for an unconfigured axis could mint the very
		// cookie the gate refuses -- a challenge loop.
		chMode = nginxconf.EffectiveJA4BotChain(verdict, *h.cfg())
	} else if forceReason != "rate_limit" {
		// ChallengeTargets.DefaultAction is the black-list chain (ua-filter
		// tab: "chain used when a black-list UA match triggers a challenge"),
		// not a global default.  Native nginx sends every escalation here as
		// forceReason="none" with no target-vs-plain distinction, so gate the
		// override on the UA actually matching a challenge target (preset /
		// extra / upstream black group).  Ungated it overrode the
		// Operating-mode pick for every plain challenge: with
		// default_action=pow_then_captcha a current-stable Chrome that failed
		// the transparent PoW was walked into the CAPTCHA leg the operator
		// only meant for black-listed UAs.
		if ua := r.Header.Get("User-Agent"); ua != "" {
			if uaListed {
				if act := strings.TrimSpace(h.cfg().Nginx.ChallengeTargets.DefaultAction); act != "" && settings.IsValidRateChallengeMode(act) {
					chMode = act
				}
				// The matched row's own chain, when it pinned one.  Same
				// precedence as the per-preset override below: the more
				// specific rule wins over the list-wide default.
				if settings.IsValidRateChallengeMode(uaRowAction) {
					chMode = uaRowAction
				}
			}
			// Per-group override: scan the UA against any upstream-rescue
			// group resolved to "black" that carries an action override.
			if grpAct := classify.ResolveActionForUA(ua,
				h.cfg().Nginx.SearchBots.UpstreamGroupMode,
				h.cfg().Nginx.SearchBots.UpstreamGroupAction); grpAct != "" && settings.IsValidRateChallengeMode(grpAct) {
				chMode = grpAct
			}
			// Per-preset override (= ChallengeTargetGroups).  Same
			// inheritance rule: an override on a preset wins over the
			// black-list default.  Skipped presets (= DisabledPresets)
			// take no action, mirroring the nginx render.
			specs := make([]classify.PresetGroupSpec, 0, len(nginxconf.ChallengeTargetGroups))
			for _, g := range nginxconf.ChallengeTargetGroups {
				specs = append(specs, classify.PresetGroupSpec{ID: g.ID, Patterns: g.Patterns})
			}
			disabledTgt := map[string]bool{}
			for _, id := range h.cfg().Nginx.ChallengeTargets.DisabledPresets {
				disabledTgt[id] = true
			}
			// A preset held for upgrade review is inert: it must not steer the
			// challenge chain mode either, matching the decision wires
			// (render.go / auth_check.go).  Without this a held target's
			// per-preset action would still upgrade pow -> captcha/deny for a
			// visitor challenged by another axis.
			for _, g := range nginxconf.ChallengeTargetGroups {
				if nginxconf.EnforcementHeld(h.cfg().Nginx, g.AddedIn) {
					disabledTgt[g.ID] = true
				}
			}
			if preAct := classify.ResolvePresetActionForUA(ua, specs,
				h.cfg().Nginx.ChallengeTargets.PresetAction,
				disabledTgt); preAct != "" && settings.IsValidRateChallengeMode(preAct) {
				chMode = preAct
			}
		}
	}
	// Community-feed chain: the operator's action for a shared-list hit, from
	// the same resolver render.go bakes into the nginx conf and auth_check
	// reads live.  Placed after the per-axis chain so it replaces whatever the
	// base picked -- the action was chosen for exactly this population.
	if cbHitKind != "" {
		chMode = h.cfg().CommunityBans.ResolvedAction()
	}
	// Stale-browser escalation.  A UA whose Chromium-family major is far behind
	// current stable is a headless-scraper tell (2026-07-15 uic.io incident);
	// serve it the operator's stale screen (default captcha_only) so a
	// PoW-solving headless engine hits the CAPTCHA it cannot cheaply clear.  The
	// stale action REPLACES the base chMode — the operator picked it precisely
	// for these UAs, so "captcha_only" must win even over a base pow_then_captcha
	// (skipping the pointless PoW leg is the intent).  The one thing it must not
	// do is soften a hard deny, so a deny base is left intact.  Safe against
	// exemptions: a bypass-IP / search-bot request never reaches ServeChallenge
	// (native protect.inc only redirects a $final_challenge=1 request here), so
	// monitoring probes are untouched.
	if g := h.cfg().Global; g.StaleBrowserEnabled() && chMode != settings.RateChallengeDeny {
		if ua := r.Header.Get("User-Agent"); classify.IsStaleBrowser(ua, g.CurrentChromeMajorResolved(),
			g.CurrentFirefoxMajorResolved(), g.FirefoxESRMajors(), g.StaleBrowserLagN(), g.FirefoxStaleLagN()) {
			chMode = g.StaleBrowserResolvedAction()
		}
	}
	// Header-integrity escalation (native): the nginx tier only signals "1"
	// with no chMode, so resolve the axis's clamped action here for a request
	// that mismatches.  Same never-soften-a-deny guard as the stale tier.  On
	// the forward-auth path headerDecide already set the reason/chMode, so this
	// only augments the native serve (a direct hit re-checks cheaply).
	if g := h.cfg().Global; chMode != settings.RateChallengeDeny && headerAxisFiresForServe(r, g) {
		chMode = g.HeaderIntegrityResolvedAction()
	}
	if cm := strings.TrimSpace(r.URL.Query().Get("chm")); cm != "" && settings.IsValidRateChallengeMode(cm) {
		chMode = cm
	}
	// Never serve a chain that cannot mint what the gate will demand.
	//
	// The requirement (a CAPTCHA-grade pass) and the screen (this chain) are
	// computed from the same settings but along different paths, and any input
	// one of them cannot see is a chance for them to disagree.  When they do,
	// the visitor is not merely inconvenienced: they solve the screen they were
	// given, present the credential it minted, are refused for holding the
	// wrong grade, and are handed the same screen again -- forever, with no way
	// out from the client side.  That is what a forward-auth node did to its
	// own operator's admin login, because the serve could not see the URI the
	// check had just matched a protected rule against.
	//
	// The resolver above is fixed, so this is the backstop: whatever route
	// picked the chain, if a CAPTCHA-grade pass is required then the chain has
	// to end in a CAPTCHA.  Escalating keeps the PoW leg, so it is never weaker
	// than what was picked, and it costs a request nothing when they agree.
	if chMode != settings.RateChallengeDeny && !chainEndsInCaptcha(chMode) {
		if requestNeedsCaptchaGrade(r.Header.Get("User-Agent"), protectedOrigURI(r, h.basePath()),
			siteFromRequest(r, h.snapshotSettings()), h.snapshotSettings()) {
			chMode = settings.RateChallengePoWThenCaptcha
		}
	}
	switch strings.TrimSpace(r.URL.Query().Get("_force")) {
	case "pow":
		chMode = settings.RateChallengePoWOnly
	case "captcha":
		chMode = settings.RateChallengeCaptchaOnly
	case "pow_then_captcha":
		chMode = settings.RateChallengePoWThenCaptcha
	}
	body = bytes.ReplaceAll(body, []byte(chmodePlaceholder),
		[]byte(`/*__CHMODE__*/"`+chMode+`"`))

	// The fingerprint this challenge is being served to, echoed back by every
	// beacon so a beacon row can say when its own connection's JA4 differs
	// (same device, different connection -- mobile Chrome does this).  Through
	// safeJA4: the header is client-influencable on a direct hit, and this
	// string lands inside a <script> block.
	body = bytes.ReplaceAll(body, []byte(serveJA4Placeholder),
		[]byte(`/*__SERVE_JA4__*/"`+safeJA4(ja4)+`"`))

	// PoW difficulty (settings.Challenge.PowDifficulty; the target
	// leading-zero-bits used by challenge.js's SHA-256 hashcash).
	//
	// This is the ONE value a site preview must NOT override.  The _bv this
	// page yields is verified AFTER the post-solve redirect, by the physical
	// host's native module (or forward-auth check) — which resolve the HOST's
	// difficulty; neither knows the previewed site (the redirect lands on the
	// host's own path, not the site-scoped one).  A previewed site whose
	// difficulty differs (typically lower) produced a PoW the physical verifier
	// rejected, so the visitor looped forever.  Branding / theme / CAPTCHA
	// provider stay overridden — the CAPTCHA path is verified by this daemon,
	// which honors the previewed site, and its cookie is host-bound, not
	// difficulty-bound.
	powDiff := ch.ResolvedPowDifficulty()
	if cfgSite != site {
		powDiff = h.cfg().Challenge.Resolve(site).ResolvedPowDifficulty()
	}
	body = bytes.ReplaceAll(body, []byte(powDiffPlaceholder),
		[]byte(fmt.Sprintf("/*__POW_DIFFICULTY__*/%d", powDiff)))
	// bv_max_entries: the roaming cap challenge.js uses when prepending the new
	// PoW signature to the _bv "~"-list (must match the Go issuer's cap).
	body = bytes.ReplaceAll(body, []byte(bvMaxEntriesPlaceholder),
		[]byte(fmt.Sprintf("/*__BV_MAX_ENTRIES__*/%d", h.cfg().Rebind.MaxEntriesResolved())))

	// PoW display floor (visible style): the operator's MinDisplayMS, holding
	// the page long enough that the check reads as a check rather than an
	// unparseable flash; the residual after a fast solve shows the "verified"
	// state.  `?_pow_display=N` (the /unmask/test/ inspection knob) overrides
	// it, clamped so a hostile query value cannot wedge the page indefinitely.
	// The floor pads only the perceived stay: pow_elapsed_ms keeps reporting
	// the pure solve time (challenge.js captures it before the hold).
	minDisplay := ch.ResolvedMinDisplayMS()
	if v := strings.TrimSpace(r.URL.Query().Get("_pow_display")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 30000 {
			minDisplay = n
		}
	}
	body = bytes.ReplaceAll(body, []byte(powMinDisplayMsPH),
		[]byte(fmt.Sprintf("/*__POW_MIN_DISPLAY_MS__*/%d", minDisplay)))

	// Challenge display style.  A preview always renders visible: the operator
	// opened the page to look at it, and the invisible style would show them a
	// blank card until the reveal timer -- the one visitor for whom that is
	// never the point.  One ReplaceAll covers both injection sites (the
	// pre-paint <head> script and window.UNMASK).
	style := ch.ResolvedDisplayStyle()
	if isPreview {
		style = settings.ChallengeDisplayVisible
	}
	body = bytes.ReplaceAll(body, []byte(challengeStylePH),
		[]byte(`/*__CHALLENGE_STYLE__*/"`+style+`"`))
	body = bytes.ReplaceAll(body, []byte(invisibleRevealPH),
		[]byte(fmt.Sprintf("/*__INVISIBLE_REVEAL_MS__*/%d", ch.ResolvedInvisibleRevealMS())))
	body = bytes.ReplaceAll(body, []byte(revealFadePH),
		[]byte(fmt.Sprintf("/*__REVEAL_FADE_MS__*/%d", ch.ResolvedRevealFadeMS())))

	// Original URI (path + query): 3-tier source.
	//   1. _orig query string (passed by nginx-rendered-protect.inc as a
	//                          rewrite arg — "the URL the user originally tried")
	//   2. rlOrigURI         (the legacy path that, when arriving via a
	//                          rate-limit hit, server.conf's
	//                          @unmask_rate_challenge location sets into the
	//                          $rl_orig_uri nginx variable and forwards to
	//                          the challenge handler)
	//   3. X-Original-URI    (= nginx $request_uri, set + anti-spoofed by the
	//                          daemon proxy) for the native BAN-challenge path:
	//                          server.inc rewrites a banned IP from its probed
	//                          URI to /unmask/challenge/ WITHOUT an _orig arg (by
	//                          design — it must not save an original a daemon-down
	//                          replay could use to bypass the ban).  $request_uri
	//                          is untouched by that internal rewrite, so the
	//                          probed URL survives in this header.  Only honor it
	//                          when it is a real off-/unmask path: a DIRECT
	//                          challenge request carries /unmask/challenge/... here
	//                          (the reason this fallback was once dropped), which
	//                          the guard rejects.  Display-only; the ban still
	//                          enforces per-request while the daemon is up.
	// Note: if all are empty, orig_path stays empty (shown as `-` in hunt).
	origPath := truncateAt(r.URL.Query().Get("_orig"), 200)
	if origPath == "" {
		origPath = truncateAt(rlOrigURI, 200)
	}
	if origPath == "" {
		origPath = banProbedOrigPath(r, h.basePath())
	}
	// Embed the original URI into window.UNMASK.orig_path.  challenge.js
	// includes it in the payload of load/pow/captcha/verify_ok/verify_ng/
	// error/cookie_err phase reports so the URL column of hunt shows it in
	// every phase (previously only serve).
	origPathJSON, _ := json.Marshal(origPath)
	body = bytes.ReplaceAll(body, []byte(origPathPlaceholder),
		append([]byte(`/*__ORIG_PATH__*/`), origPathJSON...))

	// beacon token: a short-lived signed token that challenge.js echoes back
	// in _bcDebug payload.bt.  DebugBeacon validates it to reject blind POSTs
	// / replays to /api/debug.  Also embedded in the serve event's payload
	// below so the hunt UI can group serve + all subsequent beacons (load /
	// pow / bv_*) into one session row.  Minted above, before the rebind
	// attempt, so a rebind refusal joins the same session.
	btJSON, _ := json.Marshal(beaconToken)
	body = bytes.ReplaceAll(body, []byte(beaconTokenPlaceholder),
		append([]byte(`/*__BEACON_TOKEN__*/`), btJSON...))

	// issued_at + pow_seed: both server-supplied so challenge.js relies on neither
	// the visitor's Date.now() nor a client-derived seed.  issued is computed once
	// and shared by the cookie's first segment AND the PoW seed, which binds the
	// BV secret + client IP (= cookies.PowSeed: no offline precompute, no cross-IP
	// reuse).  The server enforces a small future-skew tolerance on /verify.
	issued := time.Now().Unix()
	chIP := clientIP(r)
	chHost := requestHost(r)
	body = bytes.ReplaceAll(body, []byte(issuedAtPlaceholder),
		[]byte(fmt.Sprintf("/*__ISSUED_AT__*/%d", issued)))
	powSeedJSON, _ := json.Marshal(cookies.PowSeed(h.cfg().Secret.BVSecret, chIP, chHost, issued))
	body = bytes.ReplaceAll(body, []byte(powSeedPlaceholder),
		append([]byte(`/*__POW_SEED__*/`), powSeedJSON...))
	// ct: a server-issued, IP+time-bound proof-of-load token for the behavioral
	// CAPTCHA submit, so a forged behavioral score can't be accepted from a blind
	// POST that never fetched this challenge (see captcha.IssueToken).
	ctJSON, _ := json.Marshal(captcha.IssueToken(h.cfg().Secret.CaptchaSecretBase, chIP))
	body = bytes.ReplaceAll(body, []byte(ctTokenPlaceholder),
		append([]byte(`/*__CT__*/`), ctJSON...))
	// ref: a short support correlation id, printed in the challenge footer and
	// stored on the serve event's payload below.  When a visitor reports "the
	// challenge page won't load / I can't get through" with this id, the operator
	// runs `unmask events --ref <id>` to pull up this exact serve + its decision
	// context (verdict / flags / ip / ja4 / time).
	ref := newRef()
	// Substitute the whole visible string (label + id) so an un-substituted build
	// degrades to an empty element rather than a stray label.  The label is the
	// universal "Ref" token (refLabelText) -- same as the deny page.
	body = bytes.ReplaceAll(body, []byte(refPlaceholder), []byte(refLabelText+" "+ref))

	// "protected by unmask" credit: when OFF in settings (default), strip the
	// marker region from the HTML.  When ON, drop only the markers and keep
	// the aside body.  Operator-side previews (= /admin/test/ or ?_preview=1)
	// can override via ?_preview_show_credit=0|1 so the theme-tab iframe
	// reflects the toggle live without saving.
	showCredit := br.IsShowCredit()
	if isAdminTest := strings.Contains(r.URL.Path, "/admin/test/"); isAdminTest || strings.TrimSpace(r.URL.Query().Get("_preview")) == "1" {
		if v := strings.TrimSpace(r.URL.Query().Get("_preview_show_credit")); v == "1" {
			showCredit = true
		} else if v == "0" {
			showCredit = false
		}
	}
	body = stripOrKeepCredit(body, showCredit)

	ip := clientIP(r)
	if pkt := events.PackIP(ip); pkt != nil {
		rlInt, _ := strconv.Atoi(rl)
		testInt, _ := strconv.Atoi(test)
		payload := map[string]any{
			// ch_mode: which chain this serve offered.  force_reason says WHY
			// the challenge fired; without this the row cannot say whether the
			// visitor was about to meet a CAPTCHA or a transparent PoW, and
			// that is the difference between a rule working quietly and a rule
			// putting a puzzle in front of people.
			"force_reason": forceReason, "ch_mode": chMode, "rl": rlInt, "test": testInt,
			// Echo the beacon token so this serve row shares a group key
			// with the subsequent load / pow / bv_* beacons in the hunt UI.
			"bt": beaconToken,
			// ref: the same id printed in the page footer (support correlation).
			"ref": ref,
		}
		if origPath != "" {
			payload["orig_path"] = origPath
		}
		// referer: the page the visitor came from when they hit the challenged
		// URL (server-side from the Referer header of the original request -- a
		// native in-place serve carries it verbatim).  Used to tell "a human
		// navigating from our own pages got challenged" from a cold direct hit.
		// Often empty (bots omit it; some browsers strip cross-origin).
		if refr := refererForEvent(r); refr != "" {
			payload["referer"] = refr
		}
		// local_port: only when an LB made the client-facing port an inference
		// (see localPortNote).  Absent on every unproxied install.
		if lp := localPortNote(r, portFromRequest(r)); lp > 0 {
			payload["local_port"] = lp
		}
		// Note: we record every serve hit verbatim, including the cases where
		// a client (= Chrome prerender / double-click / LB retry) reaches us
		// twice within milliseconds.  Suppressing the second row would hide
		// real traffic and erase the operator's chance of spotting the
		// pattern + chasing the root cause.  The hunt session view collapses
		// consecutive same-phase pills in the inline chain so the visual
		// stays clean; the raw rows remain queryable via SQL / events CLI /
		// the API for anyone who wants to drill in.
		events.InsertAsync(h.DB, &events.Event{
			Site:         site,
			Host:         h.HostID,
			Scheme:       schemeFromRequest(r),
			Port:         portFromRequest(r),
			IPPacked:     pkt,
			UserAgent:    r.Header.Get("User-Agent"),
			JA4:          safeJA4(ja4),
			JA4Verdict:   verdict,
			JA4VerdictID: h.VerdictNameToID(verdict),
			Phase:        string(events.PhaseServe),
			Payload:      payload,
		})
	}

	// Challenge returns 403 by default (Cloudflare-compatible; 5xx would skew
	// site-health metrics tied to uptime monitoring).
	status := http.StatusForbidden
	// Privacy Pass / PAT (RFC 9577): when enabled, advertise a PrivateToken
	// challenge bound to this origin and switch the status to 401 -- PAT-capable
	// clients (Safari / iOS) intercept the 401, mint a token, and retry (passing
	// the privacy_pass veto axis) without ever seeing the PoW page; non-PAT
	// clients ignore the unknown auth scheme and render the page as before.
	// Bound to requestHost(r): the same host source the verifier recomputes the
	// challenge digest from, so the minted token verifies.
	if nx := h.cfg().Nginx; nx.PrivacyPassActive() {
		if wwwAuth := privacypass.BuildChallengeHeader(nx.PrivacyPass.IssuerConfigs(), requestHost(r)); wwwAuth != "" {
			w.Header().Set("WWW-Authenticate", wwwAuth)
			status = http.StatusUnauthorized
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Retry-After", "600")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.WriteHeader(status)
	_, _ = w.Write(body)

	// Burst notification (one webhook when count exceeds N in the last 5 min).  Aggregated by the notifier.
	h.Notifier.ChallengeServed()
}

// isLocalRedirect reports whether s is safe as a redirect target: a local
// absolute path ("/...") that a browser won't treat as a protocol-relative
// off-site URL ("//host" or "/\host" -- both normalize to //).  Mirrors the
// admin-login check so every redirect that echoes a request-supplied path
// (observe-only, passthrough) is open-redirect-safe.
func isLocalRedirect(s string) bool {
	return strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") && !strings.HasPrefix(s, "/\\")
}

// serveObserveOnlyRedirect is a lightweight handler that, under monitor mode,
// redirects immediately without serving a challenge.  Records the event with
// phase=serve + observe_only=1 so stats still reflect "the number of
// challenges that would fire under strict mode".  Body is a 2-tier fallback
// of `<meta http-equiv=refresh>` + `<script>location.replace()`.
func (h *Handler) serveObserveOnlyRedirect(w http.ResponseWriter, r *http.Request, site string) {
	// Restore orig_path (same 2-tier fallback as ServeChallenge).
	rlOrigURI := ""
	if i := strings.Index(r.URL.Path, "/_rl/"); i >= 0 {
		rlOrigURI = r.URL.Path[i+len("/_rl"):]
		if rlOrigURI == "" {
			rlOrigURI = "/"
		}
		if r.URL.RawQuery != "" {
			rlOrigURI += "?" + r.URL.RawQuery
		}
	}
	origPath := truncateAt(r.URL.Query().Get("_orig"), 200)
	if origPath == "" {
		origPath = truncateAt(rlOrigURI, 200)
	}
	if !isLocalRedirect(origPath) {
		// _orig is client-supplied (= "//evil.com" would be an open redirect in
		// the meta-refresh + location.replace below); fall back to root.
		origPath = "/"
	}

	// Record event (phase=serve + observe_only=1 + would_be_action=challenge).
	ip := clientIP(r)
	if pkt := events.PackIP(ip); pkt != nil {
		payload := map[string]any{
			"force_reason":    "observe_only",
			"observe_only":    1,
			"would_be_action": "challenge",
			"orig_path":       origPath,
		}
		ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
		verdict := h.resolvedVerdictName(ja4) // unmask-derived (not the X-JA4-Verdict header)
		events.InsertAsync(h.DB, &events.Event{
			Site:         site,
			Host:         h.HostID,
			Scheme:       schemeFromRequest(r),
			Port:         portFromRequest(r),
			IPPacked:     pkt,
			UserAgent:    r.Header.Get("User-Agent"),
			JA4:          safeJA4(ja4),
			JA4Verdict:   verdict,
			JA4VerdictID: h.VerdictNameToID(verdict),
			Phase:        string(events.PhaseServe),
			Payload:      payload,
		})
	}

	// Two-tier redirect to orig_path via JS / meta-refresh.  href is JSON-encoded
	// for XSS safety (origPath is attacker-controlled, derived from the user URL).
	origJSON, _ := json.Marshal(origPath)
	body := []byte(`<!doctype html><meta charset=utf-8>` +
		`<title>unmask: observe-only</title>` +
		`<meta http-equiv="refresh" content="0; url=` + htmlEscape(origPath) + `">` +
		`<script>try{location.replace(` + string(origJSON) + `)}catch(e){}</script>` +
		`<noscript>redirecting...</noscript>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("X-Unmask-Mode", "observe-only")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// htmlEscape is a minimal HTML attribute escaper for the meta-refresh URL.
// Only replaces `"` / `<` / `>` / `&` (JSON path is already safe via
// location.replace).
func htmlEscape(s string) string {
	rep := strings.NewReplacer(`&`, "&amp;", `"`, "&quot;", `<`, "&lt;", `>`, "&gt;")
	return rep.Replace(s)
}

// testPagePrefix derives the /test/ index prefix from r.URL.Path.
//
//	/unmask/admin/test/...  → /unmask/admin/test
//	/unmask/test/...        → /unmask/test
func (h *Handler) testPagePrefix(r *http.Request) string {
	base := h.cfg().Server.BasePath
	if strings.Contains(r.URL.Path, base+"/admin/test/") || strings.HasSuffix(r.URL.Path, base+"/admin/test") {
		return base + "/admin/test"
	}
	return base + "/test"
}

// TestIndex: GET {base}/test/{$} + GET {base}/admin/test/{$} shared index page.
// Shows links to the 3 sub-pages (reset-cookie / force-pow / force-captcha).
// The public-side / admin-side prefix is auto-detected from the path.
func (h *Handler) TestIndex(w http.ResponseWriter, r *http.Request) {
	prefix := h.testPagePrefix(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	body := strings.Replace(testIndexBody, "<<SITE_PICKER>>", h.testSitePickerHTML(r), 1)
	body = strings.Replace(body, "<<SITE_CFG>>", h.testSiteConfigJSON(), 1)
	_, _ = w.Write([]byte(buildTestPage(prefix, body, "")))
}

// ResetCookie: GET {base}/test/reset-cookie + GET {base}/admin/test/reset-cookie —
// Debug page that deletes the pass cookies (_bv / _br).
func (h *Handler) ResetCookie(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	expire := func(name string) *http.Cookie {
		return &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			Secure: secure, SameSite: http.SameSiteLaxMode,
		}
	}
	http.SetCookie(w, expire("_bv"))
	http.SetCookie(w, expire("_br"))
	prefix := h.testPagePrefix(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	_, _ = w.Write([]byte(buildTestPage(prefix, resetCookieBody, "Pass cookies deleted")))
}

// ForcePoW: GET {base}/test/force-pow + admin path — always serve challenge.html via the PoW path.
func (h *Handler) ForcePoW(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery == "" {
		r.URL.RawQuery = "_force=pow"
	} else {
		r.URL.RawQuery += "&_force=pow"
	}
	h.ServeChallenge(w, r)
}

// ForceCaptcha: GET {base}/test/force-captcha + admin path — always serve challenge.html via CAPTCHA.
func (h *Handler) ForceCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery == "" {
		r.URL.RawQuery = "_force=captcha"
	} else {
		r.URL.RawQuery += "&_force=captcha"
	}
	h.ServeChallenge(w, r)
}

// ForcePoWThenCaptcha: GET {base}/test/force-pow-then-captcha + admin path —
// preview the PoW → CAPTCHA chain end-to-end.  PoW runs first as on the
// terminal pow_only path, then the page hands off to the CAPTCHA stage.
func (h *Handler) ForcePoWThenCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery == "" {
		r.URL.RawQuery = "_force=pow_then_captcha"
	} else {
		r.URL.RawQuery += "&_force=pow_then_captcha"
	}
	h.ServeChallenge(w, r)
}

// PreviewRateDeny: GET {base}/admin/test/rate-deny — auth-gated preview of the
// deny-mode rate-limit page (the JS-free 403 a "deny" zone serves).  It lets an
// operator see the page WITHOUT first configuring a deny zone and tripping a
// real rate limit (which is what verifying it otherwise takes).  Query overrides
// let an unsaved selection be previewed straight from the settings form:
//
//	theme= : preview a light/dark choice (auto|light|dark); absent -> saved.
//	lang=  : force a language (fed through the same Accept-Language resolution),
//	         else the browser's Accept-Language picks it.
//
// Always 200 (a preview, not an actual block) and records no event so the
// dashboard funnel is not polluted.
func (h *Handler) PreviewRateDeny(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg()
	br := cfg.Branding.Resolve(siteFromRequest(r, h.snapshotSettings()))
	q := r.URL.Query()
	isBan := strings.TrimSpace(q.Get("kind")) == "ban"
	// Defaults come from the per-kind config -- the ban deny and the rate-limit
	// deny are designed (theme + tone) separately.  ?theme= / ?preset= override
	// so the settings page can preview an unsaved selection.
	theme := br.ResolvedDenyRateTheme()
	preset := br.ResolvedDenyRateCopyPreset()
	if isBan {
		theme = br.ResolvedDenyBanTheme()
		preset = br.ResolvedDenyBanCopyPreset()
	}
	if t := strings.TrimSpace(q.Get("theme")); t != "" {
		theme = t // renderDenyPage clamps an unknown value back to auto
	}
	// ?preset=friendly|neutral|minimal previews that tone; ?preset=inherit
	// previews the branding preset (what "inherit" resolves to); absent -> the
	// saved per-kind preset resolution.
	switch p := strings.TrimSpace(q.Get("preset")); {
	case p == "inherit":
		preset = br.ResolvedCopyPreset()
	case settings.IsValidBrandingPreset(p):
		preset = p
	}
	accept := r.Header.Get("Accept-Language")
	if l := strings.TrimSpace(q.Get("lang")); l != "" {
		accept = l
	}
	// Relax the admin's default X-Frame-Options: DENY (set in AuthMiddleware)
	// to SAMEORIGIN so the settings page can show this preview in an <iframe>.
	// Safe: the route is auth-gated and read-only (no state-changing actions),
	// and SAMEORIGIN / frame-ancestors 'self' still blocks cross-origin framing.
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// ?kind=ban previews the ban "blocked" page; anything else previews the
	// rate-limit deny page.  Preview shows a sample ref so the operator sees the
	// support-id footer in the layout; it records no event (not a real block).
	// Saved deny colors (per kind -- rate-limit and ban deny carry their own),
	// with the theme-tab-style preview override so the deny-design iframe
	// reflects unsaved edits.  Each pair applies only when both halves are hex.
	dc := denyColorsRate(br)
	if isBan {
		dc = denyColorsBan(br)
	}
	if pb, pt := q.Get("_preview_custom_light_bg"), q.Get("_preview_custom_light_text"); settings.IsValidHexColor(pb) && settings.IsValidHexColor(pt) {
		dc.LightBg, dc.LightText = pb, pt
	}
	if pb, pt := q.Get("_preview_custom_dark_bg"), q.Get("_preview_custom_dark_text"); settings.IsValidHexColor(pb) && settings.IsValidHexColor(pt) {
		dc.DarkBg, dc.DarkText = pb, pt
	}
	// Live-preview logo override: a not-yet-saved logo uploaded to the ephemeral
	// preview store, carried as a token so the deny iframe shows the picked image
	// immediately.  Token shape-checked before it is interpolated into the URL.
	// "none" previews the removed state (operator clicked remove, unsaved).
	switch raw := strings.TrimSpace(q.Get("_preview_logo")); {
	case raw == "none":
		dc.SuppressLogo = true
	case isPreviewLogoToken(raw):
		dc.LogoURL = h.previewLogoURL(raw)
	}
	if isBan {
		_, _ = w.Write(renderBanDenyC(br, preset, theme, accept, h.basePath(), newRef(), dc))
		return
	}
	_, _ = w.Write(renderRateDenyC(br, preset, theme, accept, h.basePath(), newRef(), dc))
}

// PublicTestGate: gate for the public side (/unmask/test/*).  Returns 404
// unless settings.Challenge.PublicTestPages is true.  When the per-site
// PublicTestPagesPassword is also set, the request must additionally carry
// HTTP Basic Auth whose password matches (username is ignored).  Not used
// on the admin side (/unmask/admin/test/*).
func (h *Handler) PublicTestGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := h.snapshotSettings()
		ch := cfg.Challenge.Resolve(siteFromRequest(r, cfg))
		if !ch.IsPublicTestPages() {
			http.NotFound(w, r)
			return
		}
		if pw := strings.TrimSpace(ch.PublicTestPagesPassword); pw != "" {
			_, got, ok := r.BasicAuth()
			// Constant-time compare so a remote attacker cannot probe the
			// password length one byte at a time by timing responses.
			if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(pw)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="unmask test pages", charset="UTF-8"`)
				http.Error(w, "auth required", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// testSiteHostRE: allowed shape of the {site} path segment on the site-scoped
// challenge / verify routes.  Site ids are host-derived (normalizeSite), so
// beyond the dashless short ids this also accepts dotted hostnames
// ("shop.example.com").  Bounded (RFC 1035 name length) so an oversized path
// value never reaches Resolve / logs.
var testSiteHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// hasAdminSession reports whether the request carries a valid admin session
// cookie.  Deliberately cookie-only (no DB roundtrip): callers gate read-only
// preview niceties with it, not state changes.
func (h *Handler) hasAdminSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return verifySessionCookie(h.cfg().Secret.BVSecret, c.Value) != nil
}

// testSiteOverride returns the site whose VALUES (challenge knobs / branding)
// this request may preview via the site-scoped routes (/test/site/{site}/,
// /api/{site}/verify).  Honored only for callers allowed to pick arbitrary
// sites:
//   - an admin session (the /unmask/admin/test/ picker), or
//   - the request host has public test pages ON and the operator opted in to
//     the public site picker (intranet-style deployments).
//
// Anyone else keeps the host-derived site, so the site-scoped URLs stay
// behavior-identical for regular visitors: a visitor must not get to pick a
// WEAKER site's CAPTCHA provider / difficulty for the host they are actually
// passing (see the settings help text).
func (h *Handler) testSiteOverride(r *http.Request) (string, bool) {
	s := strings.TrimSpace(r.PathValue("site"))
	if s == "" || !testSiteHostRE.MatchString(s) {
		return "", false
	}
	s = normalizeSite(s)
	if h.hasAdminSession(r) {
		return s, true
	}
	cfg := h.snapshotSettings()
	ch := cfg.Challenge.Resolve(siteFromRequest(r, cfg))
	if ch.IsPublicTestPages() && ch.IsPublicTestPagesSitePicker() {
		return s, true
	}
	return "", false
}

// testSiteConfigJSON reports what each site actually has configured, keyed by
// site ("" = the plain per-host resolution the un-scoped links use), for the
// test page's "site setting" buttons.
//
// Without it the inherit button read "default", which looks like a sixth theme
// sitting beside light / dark rather than "whatever this site is set to" --
// and there is no theme called "default".  The site picker switches sites
// without reloading, so the values ship as a map and the label follows the
// selection client-side.
func (h *Handler) testSiteConfigJSON() string {
	cfg := h.snapshotSettings()
	out := map[string]map[string]string{}
	put := func(key string, b settings.BrandingValues) {
		out[key] = map[string]string{
			"theme":  b.Theme,
			"preset": b.ResolvedCopyPreset(),
		}
		if out[key]["theme"] == "" {
			out[key]["theme"] = "auto" // what pickChallengeTheme falls back to
		}
	}
	put("", cfg.Branding.Default)
	for site := range cfg.Branding.Sites {
		put(site, cfg.Branding.Resolve(site))
	}
	// A site may have challenge settings but no branding record; it still
	// resolves to something, and the picker offers it.
	for site := range cfg.Challenge.Sites {
		if _, ok := out[site]; !ok {
			put(site, cfg.Branding.Resolve(site))
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// testSitePickerHTML builds the "Site" section of the test index page: a
// picker that re-targets the force-* links at /test/site/{site}/ so a site's
// OWN values (branding / difficulty / CAPTCHA provider) can be exercised
// end-to-end.  Empty unless the caller may pick sites (admin side always;
// public side only when the operator opted in) and at least one site has its
// own settings.
func (h *Handler) testSitePickerHTML(r *http.Request) string {
	cfg := h.snapshotSettings()
	if !strings.Contains(r.URL.Path, "/admin/test") {
		ch := cfg.Challenge.Resolve(siteFromRequest(r, cfg))
		if !ch.IsPublicTestPages() || !ch.IsPublicTestPagesSitePicker() {
			return ""
		}
	}
	seen := map[string]bool{}
	var sites []string
	for s, v := range cfg.Challenge.Sites {
		if !v.Disabled && !seen[s] {
			seen[s] = true
			sites = append(sites, s)
		}
	}
	for s, v := range cfg.Branding.Sites {
		if !v.Disabled && !seen[s] {
			seen[s] = true
			sites = append(sites, s)
		}
	}
	if len(sites) == 0 {
		return ""
	}
	sort.Strings(sites)
	var b strings.Builder
	b.WriteString(`<h2>Site</h2>
<p class="muted" style="margin:0 0 .5rem">Serve the force-* pages with a specific site's own settings (branding / PoW difficulty / CAPTCHA provider).  <code>default</code> is the plain per-host resolution.</p>
<div id="site-picker" class="theme-picker">
  <button type="button" data-site="">default</button>
`)
	for _, s := range sites {
		es := htmlEscape(s)
		b.WriteString(`  <button type="button" data-site="` + es + `">` + es + `</button>` + "\n")
	}
	b.WriteString(`</div>`)
	return b.String()
}

// buildTestPage is the HTML wrapper for the test pages.  Embeds the prefix and emits 3 links + an optional banner.
func buildTestPage(prefix, body, banner string) string {
	bannerHTML := ""
	if banner != "" {
		bannerHTML = `<div class="box"><strong>✓ ` + banner + `</strong></div>`
	}
	page := `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>unmask · test pages</title>
<meta name="robots" content="noindex,nofollow">
<style>
html{font-size:16px}
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1.5rem;color:#0f172a;line-height:1.65}
h1{font-size:1.4rem;margin:0 0 1rem}
h2{font-size:1.05rem;margin:1.5rem 0 .5rem;color:#334155}
code{background:#f1f5f9;padding:.1rem .35rem;border-radius:.15rem;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.9em}
.box{background:#f0fdf4;border:1px solid #16a34a;border-radius:.35rem;padding:.8rem 1rem;margin-bottom:1rem;color:#14532d}
ul.tests{list-style:none;padding:0;margin:.4rem 0 1rem}
ul.tests li{padding:.6rem .8rem;border:1px solid #e2e8f0;border-radius:.3rem;margin-bottom:.4rem;background:#fafbfc}
ul.tests li a{color:#2563eb;text-decoration:none;font-weight:600}
ul.tests li a:hover{text-decoration:underline}
ul.tests li .desc{display:block;color:#64748b;font-size:.85rem;margin-top:.15rem;font-weight:normal}
.muted{color:#64748b;font-size:.85rem;margin-top:1.5rem}
a{color:#2563eb;text-decoration:none}
a:hover{text-decoration:underline}
.crumbs{font-size:.85rem;color:#64748b;margin-bottom:.6rem}
.crumbs a{color:#2563eb}
/* theme picker: an on-page switcher that swaps ?theme= on the force-pow / force-captcha links. */
.theme-picker{display:flex;flex-wrap:wrap;gap:.4rem;margin:.4rem 0 1rem}
.theme-picker button{padding:.35rem .8rem;font-size:.85rem;background:#fff;color:#334155;border:1px solid #cbd5e1;border-radius:.25rem;cursor:pointer;font-family:inherit}
.theme-picker button:hover{background:#f1f5f9;border-color:#94a3b8}
.theme-picker button.active{background:#0f172a;color:#fff;border-color:#0f172a}
</style>
</head>
<body>
<p class="crumbs"><a href="/">← top</a> / <a href="<<PREFIX>>/">test</a></p>
<<BANNER>>
<<BODY>>
</body>
</html>`
	// Expand <<PREFIX>> inside body first, otherwise replacements after embedding into the page are missed.
	body = strings.ReplaceAll(body, "<<PREFIX>>", prefix)
	page = strings.ReplaceAll(page, "<<PREFIX>>", prefix)
	page = strings.ReplaceAll(page, "<<BANNER>>", bannerHTML)
	page = strings.ReplaceAll(page, "<<BODY>>", body)
	return page
}

const testIndexBody = `<h1>unmask test pages</h1>
<p>List of debug pages for sanity-check use.  Production traffic does not normally hit these URLs.</p>

<<SITE_PICKER>>

<h2>Theme</h2>
<div id="theme-picker" class="theme-picker">
  <button type="button" data-theme="" data-inherit="theme">site setting</button>
  <button type="button" data-theme="auto">auto</button>
  <button type="button" data-theme="light">light</button>
  <button type="button" data-theme="dark">dark</button>
  <button type="button" data-theme="terminal">terminal</button>
  <button type="button" data-theme="cat">cat</button>
  <button type="button" data-theme="paper">paper</button>
</div>

<h2>Wording</h2>
<p class="muted" style="margin:0 0 .5rem">Copy preset used for the challenge page text.  Preview only: this does not change what the site serves.</p>
<div id="preset-picker" class="theme-picker">
  <button type="button" data-preset="" data-inherit="preset">site setting</button>
  <button type="button" data-preset="friendly">friendly</button>
  <button type="button" data-preset="neutral">neutral</button>
  <button type="button" data-preset="minimal">minimal</button>
</div>

<h2>Language</h2>
<p class="muted" style="margin:0 0 .5rem">The challenge page picks the visitor&#39;s language from their browser; it is not a per-site setting.  Override it here to check any locale.  Preview only.</p>
<div id="lang-picker" class="theme-picker">
  <button type="button" data-lang="">visitor&#39;s browser</button>
  <button type="button" data-lang="en">en</button>
  <button type="button" data-lang="ja">ja</button>
  <button type="button" data-lang="zh">zh</button>
  <button type="button" data-lang="zht">zht</button>
  <button type="button" data-lang="ko">ko</button>
  <button type="button" data-lang="es">es</button>
  <button type="button" data-lang="pt">pt</button>
  <button type="button" data-lang="fr">fr</button>
  <button type="button" data-lang="de">de</button>
  <button type="button" data-lang="ru">ru</button>
  <button type="button" data-lang="it">it</button>
  <button type="button" data-lang="tr">tr</button>
  <button type="button" data-lang="pl">pl</button>
  <button type="button" data-lang="vi">vi</button>
  <button type="button" data-lang="th">th</button>
  <button type="button" data-lang="id">id</button>
  <button type="button" data-lang="ar">ar</button>
  <button type="button" data-lang="hi">hi</button>
</div>

<h2>PoW display time</h2>
<p class="muted" style="margin:0 0 .5rem">PoW usually finishes in tens of milliseconds on modern hardware, so the spinner is hard to inspect.  Pick a floor to hold the spinner longer for visual checks.  Test-only: production traffic always sees the real PoW solve time.</p>
<div id="pow-display-picker" class="theme-picker">
  <button type="button" data-pow-display="">none (real)</button>
  <button type="button" data-pow-display="500">500 ms</button>
  <button type="button" data-pow-display="1500">1500 ms</button>
  <button type="button" data-pow-display="3000">3000 ms</button>
  <button type="button" data-pow-display="5000">5000 ms</button>
</div>

<h2>Redirect after pass</h2>
<p class="muted" style="margin:0 0 .5rem">Override where the page navigates once PoW / CAPTCHA succeeds.  Same-origin paths only (must start with <code>/</code>, no protocol-relative <code>//host</code>).  Invalid input falls back to <code>/</code>.</p>
<input type="text" id="test-redirect-input" placeholder="/" value="/" style="font-size:.85rem;padding:.3rem .55rem;border:1px solid #cbd5e1;border-radius:.3rem;width:24rem;max-width:100%">

<h2>Tests</h2>
<ul class="tests">
  <li>
    <a href="<<PREFIX>>/reset-cookie">cookie reset</a>
    <span class="desc">Delete the pass cookies (<code>_bv</code> / <code>_br</code>) so the challenge can be re-triggered.</span>
  </li>
  <li>
    <a href="<<PREFIX>>/force-pow" data-test-link data-force="pow" target="_blank" rel="noopener">Always PoW ↗</a>
    <span class="desc">Serve challenge.html in <code>pow_only</code> mode.  Exercise the flow that forces PoW (SHA-256 hashcash).</span>
  </li>
  <li>
    <a href="<<PREFIX>>/force-pow-then-captcha" data-test-link data-force="pow_then_captcha" target="_blank" rel="noopener">PoW &rarr; CAPTCHA ↗</a>
    <span class="desc">Serve the full <code>pow_then_captcha</code> chain.  PoW first, CAPTCHA second.</span>
  </li>
  <li>
    <a href="<<PREFIX>>/force-captcha" data-test-link data-force="captcha" target="_blank" rel="noopener">Always CAPTCHA ↗</a>
    <span class="desc">Serve challenge.html in <code>captcha_only</code> mode.  Exercise the flow that forces the behavioral CAPTCHA.</span>
  </li>
</ul>
<p class="muted">Public side (<code>/unmask/test/</code>) is toggled by settings -> challenge tab "public test pages".<br>Admin side (<code>/unmask/admin/test/</code>) is always available while logged in.</p>

<script>
(function(){
  var themeButtons  = document.querySelectorAll('#theme-picker button');
  var presetButtons = document.querySelectorAll('#preset-picker button');
  var langButtons   = document.querySelectorAll('#lang-picker button');
  var powButtons    = document.querySelectorAll('#pow-display-picker button');
  var siteButtons   = document.querySelectorAll('#site-picker button');
  // What each site actually has configured, so the "site setting" button can
  // name the value it inherits instead of reading as a theme called "default".
  // Keyed by site; "" is the per-host resolution the plain force-* links use.
  var SITE_CFG = <<SITE_CFG>>;
  var redirectInp  = document.getElementById('test-redirect-input');
  var links        = document.querySelectorAll('a[data-test-link]');
  // Site-scoped serve base: /unmask/test/site/<site>/ resolves THAT site's
  // values server-side (authorized callers only); challenge.js then routes its
  // API calls to /unmask/api/<site>/ so render and verify stay consistent.
  var CH_BASE = '<<PREFIX>>'.replace(/\/(?:admin\/)?test$/, '') + '/test/site/';
  var theme  = '';
  var preset = '';
  var lang   = '';
  var pow    = '';
  var site   = '';
  var redirectTo = '';
  try { theme      = localStorage.getItem('unmask:test-theme')        || ''; } catch(e) {}
  try { preset     = localStorage.getItem('unmask:test-preset')       || ''; } catch(e) {}
  try { lang       = localStorage.getItem('unmask:test-lang')         || ''; } catch(e) {}
  try { pow        = localStorage.getItem('unmask:test-pow-display')  || ''; } catch(e) {}
  try { site       = localStorage.getItem('unmask:test-site')         || ''; } catch(e) {}
  try { redirectTo = localStorage.getItem('unmask:test-redirect-to')  || ''; } catch(e) {}
  // No picker rendered (no permission / no per-site settings): never rewrite.
  if (!siteButtons.length) site = '';
  if (redirectInp && redirectTo) redirectInp.value = redirectTo;
  // Site mode rewrites the link PATH, so keep the original force-* href around.
  links.forEach(function(a){ a.dataset.origHref = a.getAttribute('href') || ''; });
  // Show what "site setting" resolves to for the site currently selected.
  function labelInherited(){
    var cfg = SITE_CFG[site] || SITE_CFG[''] || {};
    document.querySelectorAll('[data-inherit]').forEach(function(b){
      var v = cfg[b.dataset.inherit] || '';
      b.textContent = v ? 'site setting (' + v + ')' : 'site setting';
    });
  }
  function update(){
    labelInherited();
    themeButtons.forEach(function(b){
      b.classList.toggle('active', (b.dataset.theme || '') === theme);
    });
    presetButtons.forEach(function(b){
      b.classList.toggle('active', (b.dataset.preset || '') === preset);
    });
    langButtons.forEach(function(b){
      b.classList.toggle('active', (b.dataset.lang || '') === lang);
    });
    powButtons.forEach(function(b){
      b.classList.toggle('active', (b.dataset.powDisplay || '') === pow);
    });
    siteButtons.forEach(function(b){
      b.classList.toggle('active', (b.dataset.site || '') === site);
    });
    links.forEach(function(a){
      var href = (a.dataset.origHref || '').split('?')[0];
      var qs = [];
      if (site && a.dataset.force) {
        href = CH_BASE + encodeURIComponent(site) + '/';
        qs.push('_force=' + encodeURIComponent(a.dataset.force));
      }
      if (theme) qs.push('theme=' + encodeURIComponent(theme));
      // Both are preview-only knobs; _preview=1 is what makes challenge.js
      // honour them, and it is already implied on /admin/test/.
      if (preset) { qs.push('_preview=1'); qs.push('_preview_preset=' + encodeURIComponent(preset)); }
      if (lang)   { if (!preset) qs.push('_preview=1'); qs.push('_preview_lang=' + encodeURIComponent(lang)); }
      if (pow !== '') qs.push('_pow_display=' + encodeURIComponent(pow));
      if (redirectTo && redirectTo !== '/') qs.push('_test_redirect=' + encodeURIComponent(redirectTo));
      a.setAttribute('href', qs.length ? href + '?' + qs.join('&') : href);
    });
  }
  themeButtons.forEach(function(b){
    b.addEventListener('click', function(){
      theme = b.dataset.theme || '';
      try { localStorage.setItem('unmask:test-theme', theme); } catch(e){}
      update();
    });
  });
  presetButtons.forEach(function(b){
    b.addEventListener('click', function(){
      preset = b.dataset.preset || '';
      try { localStorage.setItem('unmask:test-preset', preset); } catch(e){}
      update();
    });
  });
  langButtons.forEach(function(b){
    b.addEventListener('click', function(){
      lang = b.dataset.lang || '';
      try { localStorage.setItem('unmask:test-lang', lang); } catch(e){}
      update();
    });
  });
  siteButtons.forEach(function(b){
    b.addEventListener('click', function(){
      site = b.dataset.site || '';
      try { localStorage.setItem('unmask:test-site', site); } catch(e){}
      update();
    });
  });
  powButtons.forEach(function(b){
    b.addEventListener('click', function(){
      pow = b.dataset.powDisplay || '';
      try { localStorage.setItem('unmask:test-pow-display', pow); } catch(e){}
      update();
    });
  });
  if (redirectInp) {
    redirectInp.addEventListener('input', function(){
      var v = redirectInp.value;
      // Same client-side contract as challenge.js: only "/foo" paths
      // (not protocol-relative "//host").  Empty means "fall back to /".
      if (v === '' || (v.indexOf('/') === 0 && v.indexOf('//') !== 0)) {
        redirectTo = v;
        try { localStorage.setItem('unmask:test-redirect-to', v); } catch(e){}
        update();
      }
    });
  }
  update();
})();
</script>`

const resetCookieBody = `<h1>cookie reset</h1>
<p>Cookies deleted:</p>
<ul class="tests">
  <li><code>_bv</code><span class="desc">CAPTCHA / PoW pass cookie (HMAC-signed).</span></li>
  <li><code>_br</code><span class="desc">PoW pass marker.</span></li>
</ul>
<p>Accessing a protected path next will re-trigger the challenge.</p>
<h2>Continue testing</h2>
<ul class="tests">
  <li><a href="<<PREFIX>>/force-pow" target="_blank" rel="noopener">Always PoW ↗</a></li>
  <li><a href="<<PREFIX>>/force-pow-then-captcha" target="_blank" rel="noopener">PoW &rarr; CAPTCHA ↗</a></li>
  <li><a href="<<PREFIX>>/force-captcha" target="_blank" rel="noopener">Always CAPTCHA ↗</a></li>
</ul>`

// ServeChallengeJS: GET {base}/static/challenge.js
//
// External JS loaded from challenge.html via `<script src=>`.
// Fully static, no placeholders (the JA4 hit fact is passed inline from the
// HTML via window.UNMASK).  If ops overlays
// `/usr/share/unmask/challenge/challenge.js`, that takes priority.
func (h *Handler) ServeChallengeJS(w http.ResponseWriter, r *http.Request) {
	b, err := h.loadChallengeJS()
	if err != nil {
		log.Printf("challenge.js load failed: %v", err)
		http.Error(w, "challenge.js unavailable", http.StatusInternalServerError)
		return
	}
	writeJS(w, b)
}

func writeJS(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	// 10 minutes: challenge.js / popover-pin.js etc. are tightly coupled to
	// admin behaviour, and a settings change (= phase rename, cookie kind
	// split, etc.) needs to propagate to in-flight browsers quickly without
	// waiting for the longer 1-hour cache to bleed out.  10 min keeps the
	// per-client request count modest while shrinking the worst-case
	// staleness window by 6x.
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

func writeCSS(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

// ServePopoverPinJS / ServePopoverPinCSS: GET {base}/static/popover-pin.{js,css}
//
// Pinned popover implementation shared by every admin page (click-pin + drag
// handle (⠿) + collapse toggle (▾) + close (×)).  Used to be inline-duplicated
// in dashboard.html and hunt.html; extracted into a shared file.  Esc closes
// every pinned popover at once.  Info-tips (the `?` ball in settings) are
// also auto-wired via window.installInfoTipPinning.
func (h *Handler) ServePopoverPinJS(w http.ResponseWriter, r *http.Request) {
	b, err := assets.Static.ReadFile("static/popover-pin.js")
	if err != nil {
		http.Error(w, "popover-pin.js unavailable", http.StatusInternalServerError)
		return
	}
	writeJS(w, b)
}

func (h *Handler) ServePopoverPinCSS(w http.ResponseWriter, r *http.Request) {
	b, err := assets.Static.ReadFile("static/popover-pin.css")
	if err != nil {
		http.Error(w, "popover-pin.css unavailable", http.StatusInternalServerError)
		return
	}
	writeCSS(w, b)
}

// ServeIcon: GET {base}/static/icon.png — for the admin web UI + favicon.
// Same brand mark on the LP (unmask.sh) and admin.
// Cache-Control is short (5 min) so swapping the icon doesn't usually need a hard reload.
func (h *Handler) ServeIcon(w http.ResponseWriter, r *http.Request) {
	b, err := assets.Static.ReadFile("static/icon.png")
	if err != nil {
		http.Error(w, "icon.png unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

// ServeFlag: GET {base}/admin/static/flags/{cc}.png
//
// Small country-flag PNGs (~16x12) for the country chart.  cc is ISO 3166-1
// alpha-2 (e.g. "jp" / "us"), accepting only lowercase + digits + dash
// (prevents path traversal).  Missing files fall back to unknown.png.  All
// 251 countries + specials (unknown / lgbt / etc.) are embedded.
var flagCCRE = regexp.MustCompile(`^[a-z0-9-]{2,8}\.png$`)

func (h *Handler) ServeFlag(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !flagCCRE.MatchString(name) {
		http.Error(w, "bad flag name", http.StatusBadRequest)
		return
	}
	body, err := assets.Static.ReadFile("static/flags/" + name)
	if err != nil {
		// fallback: unknown.png (placeholder when loading fails)
		body, err = assets.Static.ReadFile("static/flags/unknown.png")
		if err != nil {
			http.Error(w, "flag not found", http.StatusNotFound)
			return
		}
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

// VerifyJSON: POST {base}/api/verify
//
// Received payload:
//   - New scheme (behavioral):  { token, sig: { mouseTrail, ... } }
//   - Old scheme (math sum):    { token, answer }
func (h *Handler) VerifyJSON(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "read"})
		return
	}
	var payload struct {
		Token  string          `json:"token"`
		Ct     string          `json:"ct"` // proof-of-load token (window.UNMASK.ct) for the behavioral path
		Answer json.RawMessage `json:"answer"`
		// IV / DT: liveness evidence for the typed math answer -- how many
		// input events the answer field saw, and how long the visitor took.
		// Pointers so "the client never reported this" (a challenge page
		// cached from before this shipped) stays distinguishable from "the
		// client reported zero", which is the machine tell.
		IV            *int            `json:"iv"`
		DT            *int            `json:"dt"`
		Sig           *captcha.Signal `json:"sig"`
		ProviderToken string          `json:"provider_token"` // release token from a 3rd-party CAPTCHA widget
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_json"})
		return
	}

	ip := clientIP(r)
	host := requestHost(r) // binds the issued _bv to this vhost
	site := siteFromRequest(r, *h.cfg())
	// Same authorized preview override as ServeChallenge: a site-scoped page
	// (/test/site/{site}/) routes its verify to /api/{site}/verify, which must
	// resolve the SAME values the page was rendered with (CAPTCHA provider /
	// threshold), else a previewed provider could never verify.  The issued
	// _bv stays bound to the physical host above.
	cfgSite := site
	if o, ok := h.testSiteOverride(r); ok {
		cfgSite = o
	}
	ch := h.cfg().Challenge.Resolve(cfgSite)
	// The _bv cookie value is dot-delimited ("<issued>.<sig>.<kind>"), so the
	// kind is kept site-agnostic: a per-site _bv binding needs a dot-safe site
	// encoding plus a site-aware native verifier — tracked as a later phase in
	// multi-site-handoff.md.
	kind := "captcha"

	// If a 3rd-party CAPTCHA provider is configured, verify with highest
	// priority (behavioral signal becomes supplementary).  For builtin,
	// proceed with the normal flow.
	if cc := ch.CaptchaProvider; cc.Provider != "" && cc.Provider != "builtin" && payload.ProviderToken != "" {
		secret := captchaSecretFor(cc)
		res, err := captcha.VerifyExternal(r.Context(), cc.Provider, secret, payload.ProviderToken, ip)
		if err != nil {
			log.Printf("captcha provider %s siteverify error: %v", cc.Provider, err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": 0, "error": "provider_unavailable"})
			return
		}
		ok := res.OK
		if cc.Provider == "recaptcha" {
			min := cc.RecaptchaMinScore
			if min <= 0 {
				min = 0.5
			}
			ok = ok && res.Score >= min
		}
		if ok {
			val := cookies.IssueValue(h.cfg().Secret.BVSecret, ip, host, kind)
			h.setBVCookie(w, r, val)
			h.mintBVJ(w, r, ip, host, kind)
			writeJSON(w, http.StatusOK, map[string]any{"ok": 1, "provider": cc.Provider, "score": round3(res.Score)})
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": 0, "error": "provider_rejected", "provider": cc.Provider, "score": round3(res.Score), "detail": res.Err,
		})
		return
	}

	if payload.Sig != nil {
		if payload.Token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "no_token"})
			return
		}
		// Proof-of-load.  The behavioral score is fully client-controlled and
		// forgeable, so without this a bot clears the CAPTCHA with a single blind
		// POST of a fabricated signal.  Require the server-issued ct token that
		// binds this IP + a recent fetch of THIS challenge page.
		if !captcha.VerifyToken(payload.Ct, h.cfg().Secret.CaptchaSecretBase, ip, 900) {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": 0, "error": "stale_challenge"})
			return
		}
		score := captcha.Score(payload.Sig, r.Header.Get("User-Agent"))
		Metrics.ObserveScore(score)
		// Zero-guard the threshold the same way the reCAPTCHA path does above:
		// a hand-edited config with provider:builtin but no builtin_score_threshold
		// yields 0, and `score >= 0` would pass every CAPTCHA (a 0.0-scoring bot
		// clears it).  defaults()/the form clamp to 0.5, but Load() does not.
		minScore := ch.CaptchaProvider.BuiltinScoreThreshold
		if minScore <= 0 {
			minScore = 0.5
		}
		if score >= minScore {
			val := cookies.IssueValue(h.cfg().Secret.BVSecret, ip, host, kind)
			h.setBVCookie(w, r, val)
			h.mintBVJ(w, r, ip, host, kind)
			writeJSON(w, http.StatusOK, map[string]any{"ok": 1, "score": round3(score)})
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": 0, "error": "low_score", "score": round3(score),
		})
		return
	}

	// Old scheme: math sum
	var ans string
	if len(payload.Answer) > 0 {
		// `answer` may arrive as a string or a number in JSON; handle both
		var s string
		if err := json.Unmarshal(payload.Answer, &s); err != nil {
			var n json.Number
			if err2 := json.Unmarshal(payload.Answer, &n); err2 == nil {
				s = string(n)
			}
		}
		ans = strings.TrimSpace(s)
	}
	if ans == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid"})
		return
	}
	// Require the proof-of-load token on the math path too (the behavioral path
	// already does).  The math token binds only the answer (a+b in [2,40], ~39
	// values), so without this a bot harvests the few answer/token pairs from
	// /api/captcha/new once and blind-POSTs them from any IP to mint _bv cookies.
	if !captcha.VerifyToken(payload.Ct, h.cfg().Secret.CaptchaSecretBase, ip, 900) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": 0, "error": "stale_challenge"})
		return
	}
	if captcha.VerifyMath(ans, payload.Token, h.cfg().Secret.CaptchaSecretBase, ip, 900) {
		// Correct arithmetic proves very little: it is the one task a headless
		// browser does better than the person this fallback exists for.  What
		// separates them is how the answer got into the field -- a person
		// produces input events on every input method there is; a script that
		// assigns .value produces none.
		//
		// A client reporting zero input events is therefore answering
		// programmatically.  It still passes (dead-ending a visitor over a
		// heuristic is the one outcome this project refuses), but the pass it
		// earns is proof-of-work grade rather than CAPTCHA grade: enough for
		// the ordinary posture, not enough where an operator demanded a
		// CAPTCHA -- a protected path, or a geo / ASN rule.  Those are exactly
		// the populations the fallback was being used to walk past.
		//
		// Absent fields mean a challenge page cached from before this shipped;
		// those keep the full grade so an upgrade never strands anyone
		// mid-answer.
		downgraded := payload.IV != nil && *payload.IV == 0
		issueKind := kind
		if downgraded {
			issueKind = "pow"
			Metrics.CountMathNoInputEvidence()
		}
		val := cookies.IssueValue(h.cfg().Secret.BVSecret, ip, host, issueKind)
		h.setBVCookie(w, r, val)
		h.mintBVJ(w, r, ip, host, issueKind)
		out := map[string]any{"ok": 1}
		if downgraded {
			out["downgraded"] = 1
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"ok": 0, "error": "wrong"})
}

// CaptchaNew: GET {base}/api/captcha/new
func (h *Handler) CaptchaNew(w http.ResponseWriter, r *http.Request) {
	a, b, token := captcha.MathChallenge(h.cfg().Secret.CaptchaSecretBase, clientIP(r))
	// ct: proof-of-load bound to this IP + time, returned with the math
	// challenge and required on the /verify math path -- so the answer/token
	// can't be harvested once and blind-replayed from any IP forever.
	ct := captcha.IssueToken(h.cfg().Secret.CaptchaSecretBase, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"a": a, "b": b, "token": token, "ct": ct})
}

// DebugBeacon: POST {base}/api/debug — JS inside the challenge HTML sends phase beacons here.
func (h *Handler) DebugBeacon(w http.ResponseWriter, r *http.Request) {
	site := siteFromRequest(r, h.snapshotSettings())
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0})
		return
	}
	var p struct {
		Phase       string `json:"phase"`
		Flags       int    `json:"flags"`
		ReloadCount int    `json:"reload_count"`
		BT          string `json:"bt"`
	}
	// Keep the raw body too and save it into the payload.
	if err := json.Unmarshal(body, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_json"})
		return
	}
	if !events.IsValidPhase(p.Phase) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_phase"})
		return
	}

	ip := clientIP(r)
	pkt := events.PackIP(ip)
	if pkt == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_ip"})
		return
	}

	// Beacon token validation: a short-lived signed token issued by the
	// server when the challenge page is served and echoed back by
	// challenge.js.  Rejects blind POSTs / expired replays (an attack where
	// a bot captures an old beacon payload to inflate phase counts).
	if !verifyBeaconToken(p.BT, h.cfg().Secret.CaptchaSecretBase, ip) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": 0, "error": "bad_token"})
		return
	}

	// per-IP rate limit (default 20 entries per 5 minutes).
	cnt, err := events.CountRecentByIP(r.Context(), h.DB, pkt, 5)
	if err == nil && cnt >= h.cfg().Challenge.Resolve(site).DebugRateLimitPer5Min {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": 0, "error": "rate_limit"})
		return
	}

	cookieBV := readCookieMax(r, "_bv", 1024) // wide enough for a full 16-entry "~"-list
	cookieBR := readCookieMax(r, "_br", 8)
	ja4 := safeJA4(strings.TrimSpace(r.Header.Get("X-Client-JA4")))
	verdict := h.resolvedVerdictName(ja4) // unmask-derived (not the X-JA4-Verdict header)

	// Save the payload too.  Decode raw JSON into a map (keep every field as-is).
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)

	_ = events.Insert(r.Context(), h.DB, &events.Event{
		Site:         site,
		Host:         h.HostID,
		Scheme:       schemeFromRequest(r),
		Port:         portFromRequest(r),
		IPPacked:     pkt,
		UserAgent:    r.Header.Get("User-Agent"),
		JA4:          ja4,
		JA4Verdict:   verdict,
		JA4VerdictID: h.VerdictNameToID(verdict),
		Phase:        p.Phase,
		Flags:        p.Flags,
		ReloadCount:  p.ReloadCount,
		CookieBV:     cookieBV,
		CookieBR:     cookieBR,
		Payload:      raw,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
}

func (h *Handler) setBVCookie(w http.ResponseWriter, r *http.Request, val string) {
	// Accumulate one per-IP signature instead of overwriting: a roaming client
	// (5G <-> wifi) keeps a valid _bv for each network it solved on, so switching
	// networks doesn't re-challenge.  AppendEntry prepends the new entry and caps
	// the list at the configured roaming cap; the native plugin + Go verify both
	// any-match it.
	existing := ""
	if c, err := r.Cookie("_bv"); err == nil {
		existing = c.Value
	}
	c := &http.Cookie{
		Name:  "_bv",
		Value: cookies.AppendEntry(existing, val, h.cfg().Rebind.MaxEntriesResolved()),
		Path:  "/",
		// CookieMaxAgeSeconds is a fixed constant -- per-site Resolve is
		// unnecessary for the browser-side Max-Age.
		MaxAge: h.cfg().Challenge.Default.CookieMaxAgeSeconds(),
		// Secure on HTTPS so the pass cookie isn't sent in cleartext on a same-
		// host http request (it's HMAC+IP bound, but don't leak it on the wire).
		// Not HttpOnly: challenge.js reads/sets _bv on the client.
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

// --------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// Use the leftmost entry (original client).  The path reaching here is assumed trusted.
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		return strings.TrimSpace(v)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

// requestHost returns the lowercased, port-stripped host the client requested.
// It binds the _bv cookie to a vhost: the issuer (here) and both verifiers (the
// Go /api/check + the C plugin via nginx $host) must compute the SAME value, so
// a cookie minted on site A can't pass on site B.  Uses the proxy-forced
// X-Original-Host (native + forward-auth both set it from $host), falling back
// to X-Forwarded-Host / r.Host.  Lowercased + port-stripped to match nginx
// $host, which the C plugin folds into its CAPTCHA HMAC / PoW seed.
func requestHost(r *http.Request) string {
	h := firstNonEmpty(
		r.Header.Get("X-Original-Host"),
		r.Header.Get("X-Forwarded-Host"),
		r.Host,
	)
	h = strings.TrimSpace(h)
	// strip an IPv6 literal's brackets + any :port, then lowercase.
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i >= 0 {
			h = h[1:i]
		}
	} else if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// adminClientHost resolves the Host the VISITOR asked for, which is not always
// the Host header that arrives.  A reverse proxy that rewrites it -- Apache's
// ProxyPass does by default, sending the backend's own address -- leaves the
// admin Host allowlist comparing "127.0.0.1:9477" against the operator's
// domains and refusing everyone, including the operator.  mod_proxy states the
// original in X-Forwarded-Host, so prefer that.
//
// Trusted-peer gated exactly like adminClientIP: the header is otherwise
// attacker-controlled, and admin_allowed_hosts is an access control.
//
// The LAST value wins, not the first.  mod_proxy APPENDS to a client-supplied
// X-Forwarded-Host rather than replacing it, so a visitor who sends
// "X-Forwarded-Host: admin.internal" makes the daemon see
// "admin.internal, shop.example.com".  Reading left-to-right -- the convention
// for X-Forwarded-For, where the original client IS the leftmost -- would let
// any visitor name any host and walk through the allowlist.  Verified against
// Apache 2.4.62 rather than assumed.
func adminClientHost(r *http.Request, cfg settings.Settings) string {
	if !peerIsTrustedProxy(r.RemoteAddr, forwardAuthTrustedPeers(cfg)) && !peerIsUnixSocket(r.RemoteAddr) {
		return r.Host
	}
	fwd := r.Header.Get("X-Forwarded-Host")
	if fwd == "" {
		return r.Host
	}
	if i := strings.LastIndexByte(fwd, ','); i >= 0 {
		fwd = fwd[i+1:]
	}
	if fwd = strings.TrimSpace(fwd); fwd == "" {
		return r.Host
	}
	return fwd
}

// adminClientIP resolves the client IP for the ADMIN allowlist check.  Unlike
// clientIP it trusts X-Real-IP / X-Forwarded-For ONLY when the connection peer
// is a configured trusted proxy -- otherwise anyone who can reach the admin
// port could spoof X-Real-IP to satisfy admin_allowed_ips.  (Mirrors the
// peer-gating /api/check already applies to forwarded JA4 / site.)
func adminClientIP(r *http.Request, cfg settings.Settings) string {
	if peerIsTrustedProxy(r.RemoteAddr, forwardAuthTrustedPeers(cfg)) {
		return clientIP(r)
	}
	// A unix-socket peer has no IP (RemoteAddr is "" / "@").  The connection is
	// local to the host and the web server in front sets X-Real-IP, so trust it
	// -- the same posture as gunicorn (unix-socket conns are trusted
	// unconditionally) and nginx (`set_real_ip_from unix:`).  Access is gated by
	// the socket file's permissions: 0660 lets only the web server's group
	// connect; 0666 lets any local process, which could spoof the header -- but
	// admin still requires a login, and the socket_mode help spells this out so
	// an operator who needs strict admin_allowed_ips can choose 0660.
	if peerIsUnixSocket(r.RemoteAddr) {
		// Trust the web server's forwarded client IP.  A bare socket connection
		// with no forwarded header (e.g. curl --unix-socket) has no client IP, so
		// return "" -- NOT the socket's "@" / "" RemoteAddr, which ipAllowed can't
		// match (ipAllowed treats "" as a socket peer and honors an allow-all list).
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
			return v
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			if i := strings.IndexByte(v, ','); i >= 0 {
				v = v[:i]
			}
			return strings.TrimSpace(v)
		}
		return ""
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

// peerIsUnixSocket reports whether the request arrived over a unix-domain
// socket: its RemoteAddr has no parseable IP ("" / "@" for an unnamed or
// abstract socket), unlike a TCP peer which is always host:port.
func peerIsUnixSocket(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return net.ParseIP(strings.Trim(host, "[]")) == nil
}

func readCookieMax(r *http.Request, name string, maxlen int) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	v := c.Value
	if len(v) > maxlen {
		v = v[:maxlen]
	}
	return v
}

// truncateAt limits s to at most n chars (safety net so long URLs don't break the dashboard layout).
func truncateAt(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// refererForEvent returns a sanitized Referer header for the hunt event payload:
// trimmed, control chars (CR/LF/tabs that could smuggle into logs) stripped, and
// capped to a sane length.  Empty when the header is absent -- the common case,
// since bots omit it and browsers strip cross-origin referers.  The value is
// display-only context (never a decision input), and the hunt UI escapes it.
func refererForEvent(r *http.Request) string {
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" {
		return ""
	}
	ref = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, ref)
	return truncateAt(ref, 300)
}

var safeJA4RE = regexp.MustCompile(`^[a-zA-Z0-9_]{8,40}$`)

// safeJA4 returns s if it looks like a valid JA4 fingerprint, else "".
func safeJA4(s string) string {
	if safeJA4RE.MatchString(s) {
		return s
	}
	return ""
}

func round3(x float64) float64 {
	return float64(int(x*1000+0.5)) / 1000
}

// VerdictRegistry builds the preset registry from current settings (for ID-based linking).
//
// Rebuilt on every call (so settings changes apply immediately).  Overhead is
// small at N=dozens.  Never returns nil.
func (h *Handler) VerdictRegistry() *nginxconf.VerdictRegistry {
	extras := h.cfg().Nginx.JA4Verdicts.Extra
	conv := make([]nginxconf.ExtraVerdict, 0, len(extras))
	for _, e := range extras {
		conv = append(conv, nginxconf.ExtraVerdict{
			ID: e.ID, Verdict: e.Verdict, Action: e.Action, Pattern: e.Pattern,
		})
	}
	return nginxconf.BuildVerdictRegistry(conv)
}

// VerdictNameToID is a convenience wrapper for name -> id.  One lookup against the registry cache.
func (h *Handler) VerdictNameToID(name string) int {
	return h.VerdictRegistry().NameToID(name)
}

// VerdictAction resolves a JA4 verdict NAME to its action ("bot"/"suspect"/"ok")
// under the current config.  Operator Extra rules win over preset groups (same
// precedence the dashboard's verdict->action map uses).  Empty for an unset or
// unknown verdict name.
func (h *Handler) VerdictAction(name string) string {
	if name == "" {
		return ""
	}
	for _, p := range h.cfg().Nginx.JA4Verdicts.Extra {
		if p.Verdict == name {
			return p.Action
		}
	}
	for _, g := range nginxconf.JA4VerdictGroups {
		for _, rule := range g.Rules {
			if rule.Verdict == name {
				return rule.Action
			}
		}
	}
	return ""
}

// verdictIsBot reports whether a JA4 verdict name resolves to a blocking action
// (bot or suspect).  An empty / unknown verdict is NOT bot, so callers that gate
// on it fail open on unclassified traffic.
func (h *Handler) verdictIsBot(name string) bool {
	a := h.VerdictAction(name)
	return a == nginxconf.JA4ActionBot || a == nginxconf.JA4ActionSuspect
}

// MethodOnly wraps `h` so requests with a different method get 405.
func MethodOnly(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, fmt.Sprintf("method %s not allowed", r.Method), http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// resolveJA4Action resolves what a JA4 verdict of action="bot" actually runs:
// the tab default, then a per-preset override, then a per-row one, each winning
// over the last.  Returns "" when the operator configured nothing, leaving the
// caller's own base in place.
//
// THE single resolver for this axis.  It used to live inline in ServeChallenge
// while the forward-auth wire had no resolution at all -- ja4Decide hardcoded
// captcha_only and never saw settings -- so every JA4 action the operator
// picked (including deny) applied on native and silently did nothing behind a
// load balancer.  Both wires call this now.
