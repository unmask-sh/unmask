// Package handlers contains the net/http handlers bound to the ServeMux by app.go.
package handlers

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/captcha"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/mail"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/nginxlog"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/user"
	"github.com/unmask-sh/unmask/admin/internal/webbotauth"
)

const (
	challengePlaceholder   = `/*__CAPTCHA_FORCE__*/"none"`
	challengeProbe         = "<!--__SUBFILTER_PROBE__-->"
	captchaPlaceholder     = "/*__CAPTCHA__*/null"
	themePlaceholder       = `/*__THEME__*/"default"`
	brandingPlaceholder    = `/*__BRANDING__*/null`
	buildVPlaceholder      = `__BUILD_V__`
	chmodePlaceholder      = `/*__CHMODE__*/"pow_then_captcha"`
	powDiffPlaceholder     = "/*__POW_DIFFICULTY__*/18"
	// PoW spinner floor.  Default 0 (= no floor, real timing); only the
	// /unmask/test/ pages override this via `?_pow_display=N` to slow the
	// spinner down for visual inspection.  Production traffic always sees
	// the real PoW solve time.
	powMinDisplayMsPH = "/*__POW_MIN_DISPLAY_MS__*/0"
	origPathPlaceholder    = `/*__ORIG_PATH__*/""`
	beaconTokenPlaceholder = `/*__BEACON_TOKEN__*/""`
	issuedAtPlaceholder    = `/*__ISSUED_AT__*/0`
	defaultSite            = "default"
)

// challengeThemes is the allowlist applied to the challenge page.  ?theme=
// query and settings value are applied only if they belong to this set
// (prevents XSS / unknown class injection).
var challengeThemes = map[string]bool{
	"default":  true,
	"dark":     true,
	"terminal": true,
	"cat":      true,
	"paper":    true,
}

// pickChallengeTheme picks one in the order ?theme= query (preview) >
// settings > "default", validates against the allowlist, and returns it.
func pickChallengeTheme(r *http.Request, configured string) string {
	if q := strings.TrimSpace(r.URL.Query().Get("theme")); q != "" {
		if challengeThemes[q] {
			return q
		}
	}
	if challengeThemes[configured] {
		return configured
	}
	return "default"
}

type Handler struct {
	DB          *db.DB
	Settings    settings.Settings
	ConfigPath  string             // settings save target (the web editing UI atomic-writes here).  Empty -> cannot save.
	Version     string             // unmask version (for display)
	HostID      string             // host identifier of this unmask instance.  Embedded in events for per-host aggregation on a shared DB.
	IPGeo       *ipgeo.Reader      // optional, may be nil/empty (mmdb unset)
	NginxLog    *nginxlog.Reader   // optional, may be nil/empty (access_log_path unset)
	BanMgr      *ban.Manager       // optional, may be nil (ban_file_path unset)
	UserRepo    *user.Repository   // internal user management (login / users tab / audit hook)
	Notifier    *notifier.Notifier // optional, may be nil (notification URL unset)
	Mailer      *mail.Mailer       // optional, may be nil (SMTP unset).  Used by alert / password reset.
	RateLimiter *ratelimit.Limiter // sliding-window counter for forward-auth mode.  nil disables counting.
	CommunityBans  *communitybans.Client // optional, may be nil.  Async submit to community feed on BAN + periodic pull.
	IPRangeSync    *nginxconf.Sync       // optional, may be nil.  Subscribe loop that pulls bypass-IP prefixes from the hub.
	WebBotAuth     *webbotauth.Verifier  // optional, may be nil.  RFC 9421 signature verification for bot requests.
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
func brandingInjectJSON(b settings.BrandingValues, basePath string) string {
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
	if p := strings.TrimSpace(b.LogoPath); p != "" {
		ext := strings.ToLower(filepath.Ext(p))
		// Allowlist of extensions we will actually serve.  Anything else is
		// treated as "no logo" so a stale config doesn't trip the visitor.
		switch ext {
		case ".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif":
			base := strings.TrimRight(basePath, "/")
			url := base + "/branding/logo"
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
	site := siteFromRequest(r)
	b := h.snapshotSettings().Branding.Resolve(site)
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
	return strings.TrimRight(h.Settings.Server.BasePath, "/")
}

// loadChallengeHTML returns the challenge.html bytes.  Order:
//
//   - settings.challenge.challenge_html_path (override for ops)
//   - /usr/share/unmask/challenge/challenge.html (RPM/deb)
//   - embedded assets/static/challenge.html (default)
func (h *Handler) loadChallengeHTML() ([]byte, error) {
	// challenge_html_path is treated as a global override (= same template
	// for every site).  Per-site challenge HTML override is out of scope for
	// v0.1 -- branding / preset / theme already cover the typical needs.
	if p := h.Settings.Challenge.Default.ChallengeHTMLPath; p != "" {
		return os.ReadFile(p)
	}
	if b, err := os.ReadFile("/usr/share/unmask/challenge/challenge.html"); err == nil {
		return b, nil
	}
	return assets.Static.ReadFile(filepath.ToSlash("static/challenge.html"))
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

	// Reason: mirror ServeChallenge's force-reason ladder so dashboards / API
	// clients see the same axis label that the HTML response would carry.
	verdict := strings.TrimSpace(r.Header.Get("X-JA4-Verdict"))
	action := strings.TrimSpace(r.Header.Get("X-JA4-Action"))
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	if action == "" && ja4 != "" {
		if _, a := matchJA4(ja4, h.Settings.Nginx); a != "" {
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
	case "captcha", "strict":
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
	site := siteFromRequest(r)
	ip := clientIP(r)
	if pkt := events.PackIP(ip); pkt != nil {
		payload := map[string]any{
			"force_reason":     reason,
			"rl":               rl,
			"non_html_client":  1,
			"method":           r.Method,
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

// ServeChallenge: GET {base}/challenge/
//
// Rate-limit path (nginx rewrites to /unmask/challenge/rl1<orig URI>): detect
// the "/rl1/" prefix, restore the original URI, and treat as rl=1.
func (h *Handler) ServeChallenge(w http.ResponseWriter, r *http.Request) {
	site := siteFromRequest(r)
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
	if forceQuery == "" && h.snapshotSettings().Challenge.Resolve(site).ObserveOnly {
		h.serveObserveOnlyRedirect(w, r, site)
		return
	}
	verdict := strings.TrimSpace(r.Header.Get("X-JA4-Verdict"))
	action := strings.TrimSpace(r.Header.Get("X-JA4-Action"))
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	// Even without the X-JA4-Action header (nginx configs that don't pass it,
	// such as GCP LB / legacy snippets), bot detection should work via
	// X-JA4-Verdict alone — re-derive the action from settings.  Verdict
	// labels are free-form strings, so prefix matching is unreliable (the
	// Action enum of preset / extra rules is the source of truth).
	if action == "" && ja4 != "" {
		if _, a := matchJA4(ja4, h.Settings.Nginx); a != "" {
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
	//	"test"       : debug paths `?_test_ja4=1` / `?_force=captcha`
	//
	// Priority is determined by overwrite order (last writer wins).
	// rate_limit / test are placed later than others to reliably override
	// debug / RL-via paths.
	forceReason := "none"
	if action == "bot" {
		forceReason = "ja4_bot"
	}
	if r.Header.Get("X-Honeypot-Hit") == "1" {
		forceReason = "honeypot"
	}
	if r.Header.Get("X-Banned") == "1" {
		forceReason = "banned"
	}
	switch strings.TrimSpace(r.Header.Get("X-Protected-Mode")) {
	case "captcha", "strict":
		forceReason = "protected"
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
	ch := h.Settings.Challenge.Resolve(site)
	br := h.Settings.Branding.Resolve(site)
	body = bytes.ReplaceAll(body, []byte(captchaPlaceholder),
		[]byte("/*__CAPTCHA__*/"+captchaInjectJSON(ch.CaptchaProvider)))
	theme := pickChallengeTheme(r, ch.Theme)
	body = bytes.ReplaceAll(body, []byte(themePlaceholder),
		[]byte(`/*__THEME__*/"`+theme+`"`))
	body = bytes.ReplaceAll(body, []byte(brandingPlaceholder),
		[]byte("/*__BRANDING__*/"+brandingInjectJSON(br, h.basePath())))
	// Cache-bust the challenge.js URL with the admin's start-time epoch so
	// every restart forces visitors to re-fetch the script.  Without this
	// the public-side max-age=600 keeps stale JS in browsers for up to 10
	// minutes after a fix lands -- painful while iterating on copy / brand.
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
	// Monitoring mode (= let every request through).  When ON we short-circuit the
	// challenge: log the signal in events, then bounce the visitor to the
	// original URL without showing PoW / CAPTCHA.
	if forceQuery == "" && h.Settings.Global.Passthrough {
		// Issue _bv so the visitor doesn't loop back through nginx's
		// challenge redirect on the next request.  Cookie shape mirrors
		// the post-PoW success path.  Skipped when ?_force= is set so
		// the operator's test endpoint can still preview the page in
		// passthrough mode.
		h.setBVCookie(w, "passthrough.0.c")
		target := "/"
		if rlOrigURI != "" {
			target = rlOrigURI
		} else if orig := strings.TrimSpace(r.URL.Query().Get("orig")); orig != "" && strings.HasPrefix(orig, "/") {
			target = orig
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	chMode := h.Settings.RateLimit.Default.ResolvedChallengeMode()
	if forceReason == "none" {
		// "no-match" path: split the chain by whether the UA looks like
		// a real browser.  Empty (= fresh install, never touched the
		// Operating mode tab) means "strict" — the default protection posture.
		ua := r.Header.Get("User-Agent")
		var pick string
		if classify.IsKnownBrowser(ua) {
			pick = h.Settings.Global.KnownBrowserAction
		} else {
			pick = h.Settings.Global.UnknownUAAction
		}
		if pick == "" {
			pick = "pow_only" // strict default
		}
		if pick != "pass" && settings.IsValidRateChallengeMode(pick) {
			chMode = pick
		}
	}
	if forceReason == "protected" {
		// Protected-path default (= per-path preset/extra dispatch wired
		// up later).  Falls through to ChallengeTargets if not set.
		if act := strings.TrimSpace(h.Settings.Nginx.ProtectedPaths.DefaultAction); act != "" && settings.IsValidRateChallengeMode(act) {
			chMode = act
		} else if act := strings.TrimSpace(h.Settings.Nginx.ChallengeTargets.DefaultAction); act != "" && settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
	} else if forceReason == "honeypot" {
		// Honeypot trip default (= preset/custom path-based override
		// wiring is a follow-up).
		if act := strings.TrimSpace(h.Settings.Nginx.Honeypot.DefaultAction); act != "" && settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
	} else if forceReason == "ja4_bot" {
		// JA4 default → preset / custom override (per verdict name).
		if act := strings.TrimSpace(h.Settings.Nginx.JA4Verdicts.DefaultAction); act != "" && settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
		if pAct := resolveJA4PresetAction(verdict, h.Settings.Nginx.JA4Verdicts); pAct != "" && settings.IsValidRateChallengeMode(pAct) {
			chMode = pAct
		}
		if eAct := resolveJA4ExtraAction(verdict, h.Settings.Nginx.JA4Verdicts); eAct != "" && settings.IsValidRateChallengeMode(eAct) {
			chMode = eAct
		}
	} else if forceReason != "rate_limit" {
		if act := strings.TrimSpace(h.Settings.Nginx.ChallengeTargets.DefaultAction); act != "" && settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
		// Per-group override: scan the UA against any upstream-rescue
		// group resolved to "black" that carries an action override.
		if ua := r.Header.Get("User-Agent"); ua != "" {
			if grpAct := classify.ResolveActionForUA(ua,
				h.Settings.Nginx.SearchBots.UpstreamGroupMode,
				h.Settings.Nginx.SearchBots.UpstreamGroupAction); grpAct != "" && settings.IsValidRateChallengeMode(grpAct) {
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
			for _, id := range h.Settings.Nginx.ChallengeTargets.DisabledPresets {
				disabledTgt[id] = true
			}
			if preAct := classify.ResolvePresetActionForUA(ua, specs,
				h.Settings.Nginx.ChallengeTargets.PresetAction,
				disabledTgt); preAct != "" && settings.IsValidRateChallengeMode(preAct) {
				chMode = preAct
			}
		}
	}
	if cm := strings.TrimSpace(r.URL.Query().Get("chm")); cm != "" && settings.IsValidRateChallengeMode(cm) {
		chMode = cm
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

	// PoW difficulty (settings.Challenge.PowDifficulty; the target
	// leading-zero-bits used by challenge.js's SHA-256 hashcash).
	body = bytes.ReplaceAll(body, []byte(powDiffPlaceholder),
		[]byte(fmt.Sprintf("/*__POW_DIFFICULTY__*/%d", ch.ResolvedPowDifficulty())))

	// PoW spinner floor.  Production sees no floor (real PoW timing); the
	// /unmask/test/ pages opt into a slowdown via `?_pow_display=N` so an
	// operator inspecting the visuals can actually see the spinner instead
	// of having it flash past.  Clamps to a safe range so a hostile query
	// value cannot wedge the page indefinitely.
	if v := strings.TrimSpace(r.URL.Query().Get("_pow_display")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 30000 {
			body = bytes.ReplaceAll(body, []byte(powMinDisplayMsPH),
				[]byte(fmt.Sprintf("/*__POW_MIN_DISPLAY_MS__*/%d", n)))
		}
	}

	// Original URI (path + query): 2-tier source.
	//   1. _orig query string (passed by nginx-rendered-protect.inc as a
	//                          rewrite arg — "the URL the user originally tried")
	//   2. rlOrigURI         (the legacy path that, when arriving via a
	//                          rate-limit hit, server.conf's
	//                          @unmask_rate_challenge location sets into the
	//                          $rl_orig_uri nginx variable and forwards to
	//                          the challenge handler)
	// Note: if both are empty, orig_path stays empty (shown as `-` in hunt).
	// We used to fall back to X-Original-URI / r.URL.RequestURI(), but:
	//   - The first is set invalid in challenge HTML's own rewrite context.
	//   - The second stored `/unmask/challenge/...` itself, hiding the
	//     user's original URI — net harm.
	// So we default to "explicitly empty when unknown".
	origPath := truncateAt(r.URL.Query().Get("_orig"), 200)
	if origPath == "" {
		origPath = truncateAt(rlOrigURI, 200)
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
	// pow / bv_*) into one session row.
	beaconToken := issueBeaconToken(h.Settings.Secret.CaptchaSecretBase, clientIP(r))
	btJSON, _ := json.Marshal(beaconToken)
	body = bytes.ReplaceAll(body, []byte(beaconTokenPlaceholder),
		append([]byte(`/*__BEACON_TOKEN__*/`), btJSON...))

	// issued_at: server unix seconds embedded into window.UNMASK so challenge.js
	// does not rely on the visitor's Date.now() (= eliminates client clock skew
	// for both the PoW seed and the cookie's first segment).  The server
	// enforces a small future-skew tolerance on /verify, but for cookies
	// minted via this exact value the relationship is always "now or earlier".
	body = bytes.ReplaceAll(body, []byte(issuedAtPlaceholder),
		[]byte(fmt.Sprintf("/*__ISSUED_AT__*/%d", time.Now().Unix())))

	// "protected by unmask" credit: when OFF in settings (default), strip the
	// marker region from the HTML.  When ON, drop only the markers and keep
	// the aside body.  Operator-side previews (= /admin/test/ or ?_preview=1)
	// can override via ?_preview_show_credit=0|1 so the theme-tab iframe
	// reflects the toggle live without saving.
	showCredit := ch.ShowCredit
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
			"force_reason": forceReason, "rl": rlInt, "test": testInt,
			// Echo the beacon token so this serve row shares a group key
			// with the subsequent load / pow / bv_* beacons in the hunt UI.
			"bt": beaconToken,
		}
		if origPath != "" {
			payload["orig_path"] = origPath
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

	// Cloudflare-compatible: challenge returns 403.
	// 5xx would skew site-health metrics tied to uptime monitoring.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Retry-After", "600")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)

	// Burst notification (one webhook when count exceeds N in the last 5 min).  Aggregated by the notifier.
	h.Notifier.ChallengeServed()
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
	if origPath == "" {
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
		verdict := strings.TrimSpace(r.Header.Get("X-JA4-Verdict"))
		ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
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
	base := h.Settings.Server.BasePath
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
	_, _ = w.Write([]byte(buildTestPage(prefix, testIndexBody, "")))
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

// PublicTestGate: gate for the public side (/unmask/test/*).  Returns 404
// unless settings.Challenge.PublicTestPages is true.  When the per-site
// PublicTestPagesPassword is also set, the request must additionally carry
// HTTP Basic Auth whose password matches (username is ignored).  Not used
// on the admin side (/unmask/admin/test/*).
func (h *Handler) PublicTestGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ch := h.snapshotSettings().Challenge.Resolve(siteFromRequest(r))
		if !ch.PublicTestPages {
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

<h2>Theme</h2>
<div id="theme-picker" class="theme-picker">
  <button type="button" data-theme="">default</button>
  <button type="button" data-theme="dark">dark</button>
  <button type="button" data-theme="terminal">terminal</button>
  <button type="button" data-theme="cat">cat</button>
  <button type="button" data-theme="paper">paper</button>
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
    <a href="<<PREFIX>>/force-pow" data-test-link target="_blank" rel="noopener">Always PoW ↗</a>
    <span class="desc">Serve challenge.html in <code>pow_only</code> mode.  Exercise the flow that forces PoW (SHA-256 hashcash).</span>
  </li>
  <li>
    <a href="<<PREFIX>>/force-pow-then-captcha" data-test-link target="_blank" rel="noopener">PoW &rarr; CAPTCHA ↗</a>
    <span class="desc">Serve the full <code>pow_then_captcha</code> chain.  PoW first, CAPTCHA second.</span>
  </li>
  <li>
    <a href="<<PREFIX>>/force-captcha" data-test-link target="_blank" rel="noopener">Always CAPTCHA ↗</a>
    <span class="desc">Serve challenge.html in <code>captcha_only</code> mode.  Exercise the flow that forces the behavioral CAPTCHA.</span>
  </li>
</ul>
<p class="muted">Public side (<code>/unmask/test/</code>) is toggled by settings -> challenge tab "public test pages".<br>Admin side (<code>/unmask/admin/test/</code>) is always available while logged in.</p>

<script>
(function(){
  var themeButtons = document.querySelectorAll('#theme-picker button');
  var powButtons   = document.querySelectorAll('#pow-display-picker button');
  var redirectInp  = document.getElementById('test-redirect-input');
  var links        = document.querySelectorAll('a[data-test-link]');
  var theme = '';
  var pow   = '';
  var redirectTo = '';
  try { theme      = localStorage.getItem('unmask:test-theme')        || ''; } catch(e) {}
  try { pow        = localStorage.getItem('unmask:test-pow-display')  || ''; } catch(e) {}
  try { redirectTo = localStorage.getItem('unmask:test-redirect-to')  || ''; } catch(e) {}
  if (redirectInp && redirectTo) redirectInp.value = redirectTo;
  function update(){
    themeButtons.forEach(function(b){
      b.classList.toggle('active', (b.dataset.theme || '') === theme);
    });
    powButtons.forEach(function(b){
      b.classList.toggle('active', (b.dataset.powDisplay || '') === pow);
    });
    links.forEach(function(a){
      var href = (a.getAttribute('href') || '').split('?')[0];
      var qs = [];
      if (theme) qs.push('theme=' + encodeURIComponent(theme));
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
	for _, p := range []string{
		"/usr/share/unmask/challenge/challenge.js",
	} {
		if b, err := os.ReadFile(p); err == nil {
			writeJS(w, b)
			return
		}
	}
	b, err := assets.Static.ReadFile("static/challenge.js")
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
		Token         string          `json:"token"`
		Answer        json.RawMessage `json:"answer"`
		Sig           *captcha.Signal `json:"sig"`
		ProviderToken string          `json:"provider_token"` // release token from a 3rd-party CAPTCHA widget
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_json"})
		return
	}

	ip := clientIP(r)
	site := siteFromRequest(r)
	ch := h.Settings.Challenge.Resolve(site)
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
			val := cookies.IssueValue(h.Settings.Secret.BVSecret, ip, kind)
			h.setBVCookie(w, val)
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
		score := captcha.Score(payload.Sig)
		Metrics.ObserveScore(score)
		if score >= ch.CaptchaProvider.BuiltinScoreThreshold {
			val := cookies.IssueValue(h.Settings.Secret.BVSecret, ip, kind)
			h.setBVCookie(w, val)
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
	if captcha.VerifyMath(ans, payload.Token, h.Settings.Secret.CaptchaSecretBase) {
		val := cookies.IssueValue(h.Settings.Secret.BVSecret, ip, kind)
		h.setBVCookie(w, val)
		writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"ok": 0, "error": "wrong"})
}

// CaptchaNew: GET {base}/api/captcha/new
func (h *Handler) CaptchaNew(w http.ResponseWriter, r *http.Request) {
	a, b, token := captcha.MathChallenge(h.Settings.Secret.CaptchaSecretBase)
	writeJSON(w, http.StatusOK, map[string]any{"a": a, "b": b, "token": token})
}

// DebugBeacon: POST {base}/api/debug — JS inside the challenge HTML sends phase beacons here.
func (h *Handler) DebugBeacon(w http.ResponseWriter, r *http.Request) {
	site := siteFromRequest(r)
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
	if !verifyBeaconToken(p.BT, h.Settings.Secret.CaptchaSecretBase, ip) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": 0, "error": "bad_token"})
		return
	}

	// per-IP rate limit (default 20 entries per 5 minutes).
	cnt, err := events.CountRecentByIP(r.Context(), h.DB, pkt, 5)
	if err == nil && cnt >= h.Settings.Challenge.Resolve(site).DebugRateLimitPer5Min {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": 0, "error": "rate_limit"})
		return
	}

	cookieBV := readCookieMax(r, "_bv", 80)
	cookieBR := readCookieMax(r, "_br", 8)
	ja4 := safeJA4(strings.TrimSpace(r.Header.Get("X-Client-JA4")))
	verdict := strings.TrimSpace(r.Header.Get("X-JA4-Verdict"))

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

func (h *Handler) setBVCookie(w http.ResponseWriter, val string) {
	c := &http.Cookie{
		Name:     "_bv",
		Value:    val,
		Path:     "/",
		// CookieMaxAgeSeconds is a fixed constant -- per-site Resolve is
		// unnecessary for the browser-side Max-Age.
		MaxAge:   h.Settings.Challenge.Default.CookieMaxAgeSeconds(),
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
	extras := h.Settings.Nginx.JA4Verdicts.Extra
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

// resolveJA4PresetAction returns the per-preset chMode override for the
// preset that owns the given verdict name.  Empty = no override (caller
// should keep the previous chMode value).  Disabled presets are skipped to
// mirror the nginx render's exclusion.
func resolveJA4PresetAction(verdict string, c settings.JA4VerdictsConfig) string {
	if verdict == "" || len(c.PresetAction) == 0 {
		return ""
	}
	disabled := map[string]bool{}
	for _, id := range c.DisabledPresets {
		disabled[id] = true
	}
	for _, g := range nginxconf.JA4VerdictGroups {
		if disabled[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			if r.Verdict == verdict {
				return c.PresetAction[g.ID]
			}
		}
	}
	return ""
}

// resolveJA4ExtraAction walks the user-defined Extra rules and returns the
// per-row chMode override aligned by index with the matching verdict name.
// Disabled rows are ignored.  Empty = no override.
func resolveJA4ExtraAction(verdict string, c settings.JA4VerdictsConfig) string {
	if verdict == "" || len(c.Extra) == 0 || len(c.ExtraAction) == 0 {
		return ""
	}
	for i, e := range c.Extra {
		if e.Verdict != verdict {
			continue
		}
		if i < len(c.ExtraDisabled) && c.ExtraDisabled[i] {
			continue
		}
		if i < len(c.ExtraAction) {
			return strings.TrimSpace(c.ExtraAction[i])
		}
	}
	return ""
}
