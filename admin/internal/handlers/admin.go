// dashboard / admin endpoints.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	stdhtml "html"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// tzCookieName is the cookie written by the TZ picker.  nil value = browser auto.
const tzCookieName = "unmask_tz"

// resolveTZ reads the TZ from the cookie.  Whatever IANA tz name the picker UI
// wrote is used directly.  Empty ("browser-auto" selected) returns "" and the
// template / JS side resolves with Intl auto.
//
// The picker JS writes the cookie via encodeURIComponent(), so "Asia/Tokyo"
// arrives as "Asia%2FTokyo" — decodeCookieValue undoes that.  Without the
// decode the '%' fails the allowlist below and the operator silently falls
// back to UTC.
func resolveTZ(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(tzCookieName)
	if err != nil || c == nil {
		return ""
	}
	v := decodeCookieValue(c.Value)
	if v == "browser" || v == "auto" {
		return ""
	}
	// safety: cookie value is expected to be an IANA tz name (e.g. "Asia/Tokyo").  Accept only alnum + / + _ + -.
	for _, ch := range v {
		if (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') &&
			(ch < '0' || ch > '9') && ch != '/' && ch != '_' && ch != '-' && ch != '+' {
			return ""
		}
	}
	return v
}

// resolveLocation maps the cookie TZ to a *time.Location for server-side day
// bucketing of dashboard / stats queries.  Empty cookie or unknown name falls
// back to time.UTC (= raw storage TZ), so a broken cookie value does not
// crash chart rendering -- it just renders in UTC.  The template / JS side
// keeps using resolveTZ() as the display TZ for individual <time data-ts>.
func resolveLocation(r *http.Request) *time.Location {
	name := resolveTZ(r)
	if name == "" {
		return time.UTC
	}
	if loc, err := time.LoadLocation(name); err == nil && loc != nil {
		return loc
	}
	return time.UTC
}

// parseCustomRange resolves a custom-range request's from/to calendar dates
// (YYYY-MM-DD, interpreted in the operator's TZ) to a UTC window in unix
// seconds: [from 00:00:00, to 23:59:59].  Returns 0,0 when either date is
// missing or unparseable, which the caller treats as "fall back to a preset".
func parseCustomRange(fromStr, toStr string, loc *time.Location) (int64, int64) {
	from, err1 := time.ParseInLocation("2006-01-02", strings.TrimSpace(fromStr), loc)
	to, err2 := time.ParseInLocation("2006-01-02", strings.TrimSpace(toStr), loc)
	if err1 != nil || err2 != nil {
		return 0, 0
	}
	return from.Unix(), to.Add(24*time.Hour - time.Second).Unix()
}

var (
	dashboardTmpl     *template.Template
	dashboardTmplOnce sync.Once
	dashboardTmplErr  error
)

func loadDashboardTemplate() (*template.Template, error) {
	dashboardTmplOnce.Do(func() {
		funcs := template.FuncMap{
			// assetv: cache-buster for the shared static assets
			// (popover-pin.css / .js).  They are served with max-age caching
			// and were linked bare, so after a binary swap every browser kept
			// the previous build's copy for up to an hour -- new page HTML
			// driving old JS/CSS, which is how a fix can be deployed and a
			// fresh reload still shows the old behaviour.  Same stamp
			// challenge.js already uses (process start), so one restart moves
			// every asset forward together.
			"assetv": func() int64 { return buildVersionStamp },
			// dict builds a map from alternating key/value args, for passing a
			// small bundle of named values into a {{ template }} partial.
			"dict": func(kv ...any) map[string]any {
				m := make(map[string]any, len(kv)/2)
				for i := 0; i+1 < len(kv); i += 2 {
					k, _ := kv[i].(string)
					m[k] = kv[i+1]
				}
				return m
			},
			"hasPrefix": strings.HasPrefix,
			"replace":   strings.ReplaceAll,
			"lower":     strings.ToLower,
			"percent": func(x float64) string {
				return fmt.Sprintf("%.1f%%", x*100)
			},
			"score": func(x float64) string {
				return fmt.Sprintf("%.2f", x)
			},
			"add": func(a, b int) int { return a + b },
			"sub": func(a, b int) int { return a - b },
			"mul": func(a, b int) int { return a * b },
			"min": func(a, b int) int {
				if a < b {
					return a
				}
				return b
			},
			"max": func(a, b int) int {
				if a > b {
					return a
				}
				return b
			},
			// paginationPages: full numbered pager helper.
			//
			// Returns the sequence of page numbers to render in the pager, with
			// 0 acting as an "..." (ellipsis) marker.  Inspired by the parent
			// repo's PageNavigator (= current ± round window + first/last outer
			// blocks, joined with ellipses where there are gaps).
			//
			//   current    -- 1-indexed current page (1..total)
			//   total      -- total pages (>= 1)
			//   round      -- pages to show on each side of current (e.g. 2 → ±2)
			//   outer      -- pages to anchor at the head and the tail (e.g. 1)
			//
			// Empty / nil for total <= 0.  Single-page case returns [1].
			"paginationPages": func(current, total, round, outer int) []int {
				if total <= 0 {
					return nil
				}
				if round < 0 {
					round = 0
				}
				if outer < 0 {
					outer = 0
				}
				present := make(map[int]bool, 2*round+2*outer+1)
				add := func(p int) {
					if p >= 1 && p <= total {
						present[p] = true
					}
				}
				// First outer block (= expand when current is near the start).
				headBlock := outer
				if round > current {
					headBlock = round * 3
				}
				for p := 1; p <= headBlock; p++ {
					add(p)
				}
				// Tail outer block (= expand when current is near the end).
				tailFrom := total - outer + 1
				if total-round < current {
					tailFrom = total - round*2 + 1
				}
				for p := tailFrom; p <= total; p++ {
					add(p)
				}
				// Current window.
				for p := current - round; p <= current+round; p++ {
					add(p)
				}
				keys := make([]int, 0, len(present))
				for k := range present {
					keys = append(keys, k)
				}
				sort.Ints(keys)
				out := make([]int, 0, len(keys)*2)
				var last int
				for _, k := range keys {
					if last > 0 && k > last+1 {
						out = append(out, 0) // ellipsis sentinel
					}
					out = append(out, k)
					last = k
				}
				return out
			},
			// Render an integer with thousands separators (1234 -> "1,234").  Same format as the parent project.
			"comma": func(n int) string {
				s := fmt.Sprintf("%d", n)
				neg := false
				if strings.HasPrefix(s, "-") {
					neg = true
					s = s[1:]
				}
				out := ""
				for i, c := range s {
					if i > 0 && (len(s)-i)%3 == 0 {
						out += ","
					}
					out += string(c)
				}
				if neg {
					out = "-" + out
				}
				return out
			},
			// Ratio formatter: returns "-" when load=0 (or denom=0).
			"rate": func(num, denom int) string {
				if denom <= 0 {
					return "-"
				}
				return fmt.Sprintf("%.1f%%", float64(num)/float64(denom)*100)
			},
			// Bypass HTML escaping (used to embed <code> etc. in descriptions).
			"safeHTML": func(s string) template.HTML { return template.HTML(s) },
			// pctOf: share of a total, for the composition bar's segment widths.
			// Returns a plain number so the template can put it straight into a
			// width; a zero total is 0 rather than a divide by zero.
			"pctOf": func(n, total int) string {
				if total <= 0 || n <= 0 {
					return "0"
				}
				return strconv.FormatFloat(float64(n)/float64(total)*100, 'f', 4, 64)
			},
			// pctLabel: the same share, rounded for reading.  A share that is
			// present but rounds to 0.0 shows as "<0.1%" -- a legend entry
			// reading 0.0% beside a non-zero count looks like a broken figure.
			// ruleRowState centralises the rejected-save row decoration every
			// rule-list template needs: whether this row opens for editing
			// (it was changed) and whether it is the one the error points at.
			// Before this the same nested {{ if }} chain was pasted into a
			// dozen inline blocks; one tested helper replaces all of them.
			"ruleRowState": func(value, field, errField, errValue, errMsg string, focus map[string]bool) ruleRowSt {
				st := ruleRowSt{}
				if focus[value] {
					st.editing = true
				}
				if errMsg != "" && field == errField {
					if errValue != "" {
						st.Err = value == errValue
					} else {
						st.Err = focus[value] // whole-field error: mark the changed rows
					}
				}
				var cls string
				if st.editing {
					cls += " editing"
				}
				if st.Err {
					cls += " rule-row-error"
				}
				st.Class = cls
				return st
			},
			"pctLabel": func(n, total int) string {
				if total <= 0 || n <= 0 {
					return "0%"
				}
				p := float64(n) / float64(total) * 100
				if p < 0.05 {
					return "<0.1%"
				}
				return strconv.FormatFloat(p, 'f', 1, 64) + "%"
			},
			// uaSummary condenses a browser UA to "<platform> · <browser> <major>"
			// for the events table; "" for anything that is not a recognisable
			// browser, so the caller keeps the raw string (see classify.UASummary
			// for why bots deliberately do not summarise).  Lives here rather
			// than on events.Row so the events package stays independent of
			// classify.
			"uaSummary": classify.UASummary,
			// patText / patLiteral: a stored pattern may declare itself literal
			// with a marker.  The row shows the text the operator typed and says
			// separately how it is read -- the marker itself is plumbing.
			"patText":    settings.PatternText,
			"patLiteral": settings.IsLiteralPattern,
			"patMode":    func(p string) string { return string(settings.PatternModeOf(p)) },
			// Every row says how it is read, including the regex ones: with a new
			// row defaulting to "contains", a blank badge would mark the unusual
			// case as the ordinary one.
			"patModeLabel": func(lang i18n.Lang, p string) string {
				switch settings.PatternModeOf(p) {
				case settings.ModeContains:
					return strings.ReplaceAll(i18n.T(lang, "settings.rule.pat_contains"), "\n", "")
				case settings.ModeExact:
					return strings.ReplaceAll(i18n.T(lang, "settings.rule.pat_exact"), "\n", "")
				case settings.ModeSubdomain:
					return strings.ReplaceAll(i18n.T(lang, "settings.rule.pat_subdomain"), "\n", "")
				}
				return strings.ReplaceAll(i18n.T(lang, "settings.rule.pat_regex"), "\n", "")
			},
			// uaCrawler: is this UA a listed crawler?  The hunt log marks
			// those rows -- a crawler in the CHALLENGE log is one that did
			// not pass verification, which is what an operator hunting
			// spoofs is scanning for.
			// uaRuleToken: what the hunt ranking proposes as a black-list
			// pattern for this UA -- the name it calls itself, or "" when it
			// only claims to be a browser.
			"uaRuleToken":    classify.UARuleToken,
			"uaPlatformIcon": classify.UAPlatformIcon,
			"uaBrowserColor": classify.UABrowserColor,
			"uaBrowserIcon":  classify.UABrowserIcon,
			"uaSummaryPlat": func(sum string) string {
				p, _ := classify.UASummaryParts(sum)
				return p
			},
			// axisSeed*: placeholder thresholds for the default card's axis
			// rows (adopted verbatim when a row is enabled with blank fields).
			"axisSeedRPM":   settings.AxisSeedRPM,
			"axisSeedBurst": settings.AxisSeedBurst,
			"uaSummaryBrowser": func(sum string) string {
				_, b := classify.UASummaryParts(sum)
				return b
			},
			// uaBotKind: "" (not a bot) | "listed" | "self".
			//
			// The two are worth telling apart.  A LISTED crawler is one whose
			// vendor is known and, for the big ones, publishes egress ranges
			// -- so a listed name sitting in the challenge log means the
			// request failed that verification, which is the spoof signal.  A
			// SELF-declared bot is simply a client that says it is one: there
			// is no list, no ranges and nothing it could have failed, so
			// marking it the same way would claim a verification that never
			// existed.
			"uaBotKind": func(ua string) string {
				if c, _ := classify.LookupCrawler(ua); c != "" && c != "other" {
					return "listed"
				}
				if classify.SelfDeclaredBot(ua) != "" {
					return "self"
				}
				return ""
			},
			// toJSON marshals a value for embedding in a <script> block or as a
			// JS literal.  Returned as template.JS so it lands as a literal
			// rather than being re-quoted into a JS string; that is safe here
			// because encoding/json escapes <, > and & inside strings, so a
			// value containing "</script>" cannot close the element.
			"toJSON": func(v any) template.JS {
				b, err := json.Marshal(v)
				if err != nil {
					return template.JS("null")
				}
				return template.JS(b)
			},
			// htmlEscapeText: EXTRA-escape a value destined for a data-* attribute
			// that JS later reads via .dataset (which HTML-decodes) and injects
			// with innerHTML.  Without this double-escape the decode+raw-inject
			// re-animates markup = stored XSS (= the community-bans feed .Reasoning
			// popover).  text/template's own attribute escaping is one layer; this
			// adds the second so the decoded value renders as literal text.
			"htmlEscapeText": stdhtml.EscapeString,
			// ccImg converts ISO 3166-1 alpha-2 into the <x> portion of /static/flags/<x>.png.
			//   "JP"    -> "jp" (lowercase)
			//   ""      -> "unknown" (IP-geo miss; falls back to unknown.png)
			//   non-2ch -> "unknown"
			"ccImg": func(cc string) string {
				if len(cc) != 2 {
					return "unknown"
				}
				return strings.ToLower(cc)
			},
			// ccLabel: alt / title for the img.  Empty / invalid -> "??".
			"ccLabel": func(cc string) string {
				if len(cc) != 2 {
					return "??"
				}
				return cc
			},
			// Short aliases for calling i18n.T / i18n.Tf from templates.
			//   {{ t .Lang "nav.sites" }}
			//   {{ tf .Lang "dashboard.range_text" .Range .StartedAt }}
			"t": func(lang i18n.Lang, key string) string {
				return i18n.T(lang, key)
			},
			"tf": func(lang i18n.Lang, key string, args ...any) string {
				return i18n.Tf(lang, key, args...)
			},
			// rateStr: a nullable rate pointer -> its string, "" when nil
			// (inherit).  Lets the geo tab render GeoRule.RatePerMin directly
			// (the ASN tab pre-flattens rows Go-side; geo ranges the config).
			"rateStr": rateStr,
			// helpJSON: for dashboard help-popover.  Returns dict "help.*" as JSON.
			// html/template auto-escapes strings inside <script> as JS literals,
			// double-quoting them (= "{\"...\":\"...\"}").  Wrap as template.JS to
			// emit the raw JSON literal.  safeHTML would still be treated as a JS
			// string literal inside <script>.
			"helpJSON": func(lang i18n.Lang) template.JS {
				return template.JS(i18n.HelpJSON(lang))
			},
			// reverse returns a new slice that reverses the given one (used when the
			// chart wants ascending data but the adjacent table should show
			// descending).  The original slice is not modified.
			"reverse": func(s any) any {
				v := reflect.ValueOf(s)
				if v.Kind() != reflect.Slice {
					return s
				}
				n := v.Len()
				out := reflect.MakeSlice(v.Type(), n, n)
				for i := 0; i < n; i++ {
					out.Index(n - 1 - i).Set(v.Index(i))
				}
				return out.Interface()
			},
			// weekday returns a short locale-aware day-of-week label for a
			// "YYYY-MM-DD" date string.  Bad input -> "".  Falls back to the
			// English short form when the language is unknown.
			"weekday": func(date string, lang i18n.Lang) string {
				t, err := time.Parse("2006-01-02", date)
				if err != nil {
					return ""
				}
				ja := []string{"日", "月", "火", "水", "木", "金", "土"}
				en := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
				if lang == "ja" {
					return ja[t.Weekday()]
				}
				return en[t.Weekday()]
			},
			// firstN returns the first n elements of slice s (= caps a table to
			// a few rows without trimming the underlying data). Non-slice / n<0
			// returns s unchanged; n past the end is clamped.
			// clip: shorten a value for display, leaving the full string to the
			// cellpop popover (data-full-value).  Rune-based, so a multi-byte
			// value is never cut mid-character.
			"clip": func(n int, s string) string {
				r := []rune(s)
				if n < 1 || len(r) <= n {
					return s
				}
				return string(r[:n]) + "\u2026"
			},
			"firstN": func(n int, s any) any {
				v := reflect.ValueOf(s)
				if v.Kind() != reflect.Slice || n < 0 {
					return s
				}
				if n > v.Len() {
					n = v.Len()
				}
				return v.Slice(0, n).Interface()
			},
		}
		sub, err := fs.Sub(assets.Templates, "templates")
		if err != nil {
			dashboardTmplErr = err
			return
		}
		dashboardTmpl, dashboardTmplErr = template.New("dashboard.html").
			Funcs(funcs).ParseFS(sub, "*.html")
	})
	return dashboardTmpl, dashboardTmplErr
}

// sessionCtxKey is the key used to inject SessionPayload into r.Context().
type sessionCtxKey struct{}

// SessionFromContext returns the current user (role / id) inside a handler.  nil when not authenticated.
func SessionFromContext(r *http.Request) *SessionPayload {
	v, _ := r.Context().Value(sessionCtxKey{}).(*SessionPayload)
	return v
}

// AuthMiddleware handles authentication / authorization for admin endpoints.
//
// If the session cookie HMAC is valid, inject SessionPayload into the context and call next.
// Otherwise:
//   - HTML paths     -> 302 to /admin/login
//   - API paths (/admin/api/...) -> 401 JSON
//
// `admin_token` auth has been removed; only the internal user DB + login form remains.
func (h *Handler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Security headers on every admin response.  X-Frame-Options + CSP
		// frame-ancestors stop the admin UI being framed (clickjacking of
		// state-changing actions); nosniff + Referrer-Policy are safe hardening.
		// (A script-src CSP that would also block injected inline handlers needs
		// the admin's inline <script>s moved to nonces first -- a follow-up; the
		// round-3 stored XSS is already fixed at the escaping source.)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		// Admin pages are per-operator, data-driven, and redeployed often.  With
		// no Cache-Control the browser applies heuristic caching and serves a
		// stale dashboard after a redeploy (the inline <style>/markup that make
		// up a page ride in its HTML, so a cached page hides every UI change).
		// Default every admin response to no-store; handlers that serve cacheable
		// bytes (preview images, short-poll JSON) override it with their own Set.
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		// During the install wizard, redirect every admin path to /admin/setup/.
		if needed, _ := h.SetupNeeded(r); needed {
			http.Redirect(w, r, h.cfg().Server.BasePath+"/admin/setup/", http.StatusFound)
			return
		}
		// Check the remote IP against the admin_allowed_ips list (enforced at the
		// handler layer so deployments that don't include the rendered nginx conf
		// still get the restriction).
		ip := adminClientIP(r, h.snapshotSettings())
		if allowIPs := settings.EnabledValues(h.cfg().Nginx.AdminAllowedIPs, h.cfg().Nginx.AdminAllowedIPsDisabled); !ipAllowed(ip, allowIPs) {
			log.Printf("admin IP denied: ip=%s path=%s allow_from=%v", ip, r.URL.Path, allowIPs)
			adminIPForbidden(w, ip)
			return
		}
		// Carry the resolved client address to the audit log.  Done here rather
		// than at each of Record's ~30 call sites: this is the one place that
		// already knows the real address behind the proxy, and a call site added
		// later inherits it instead of quietly logging an action from nowhere.
		r = r.WithContext(user.WithClientIP(r.Context(), ip))
		secret := h.cfg().Secret.BVSecret
		if c, err := r.Cookie(sessionCookieName); err == nil {
			if pay := verifySessionCookie(secret, c.Value); pay != nil {
				// Re-check the user against the DB so a deleted or demoted account
				// loses access immediately instead of riding its cookie's frozen
				// role for up to 30 days.  Honor the CURRENT DB role (not the
				// cookie's); a transient DB error keeps the session (fail-open) so
				// a blip doesn't log every admin out.
				if h.UserRepo != nil {
					if u, uerr := h.UserRepo.GetByID(r.Context(), pay.UserID); uerr == nil && u != nil {
						if u.Disabled {
							// A suspended account loses its session on the very
							// next request — same treatment as a deleted one.
							// This immediacy is the point of disabling: it cuts
							// access faster than a password change ever could.
							sec := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
							http.SetCookie(w, clearSessionCookie(sec))
							http.Redirect(w, r, h.cfg().Server.BasePath+"/admin/login", http.StatusFound)
							return
						}
						pay.Role = u.Role
					} else if errors.Is(uerr, user.ErrNotFound) {
						sec := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
						http.SetCookie(w, clearSessionCookie(sec))
						http.Redirect(w, r, h.cfg().Server.BasePath+"/admin/login", http.StatusFound)
						return
					}
				}
				// Sliding extension on each request: refresh when remaining lifetime drops below half of TTL.
				secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
				if sessionNeedsRefresh(pay) {
					http.SetCookie(w, issueSessionCookie(secret, pay.UserID, pay.Role, secure, pay.Remember))
					// Slide the CSRF cookie WITH the session (same value, fresh
					// expiry).  Minted only at login, it used to expire ~30 days
					// in while the session slid on forever -- the state that fed
					// the backfill below on every operator, every TTL period.
					if tok := CSRFTokenFromRequest(r); tok != "" {
						http.SetCookie(w, issueCSRFCookie(tok, secure, pay.Remember))
					}
				}
				// Backfill the CSRF cookie when the session outlived it (the
				// session slides forward on every request, the CSRF cookie is
				// only minted at login -- so ~30 days after login it expires
				// alone) or for sessions issued before the CSRF roll-out.
				// Issue the cookie AND hand the token to this same request
				// (withIssuedCSRFToken), so the page renders its forms with
				// the value whose Set-Cookie is on this response.  Never
				// self-redirect to "pick the cookie up": a client that does
				// not return it -- Chrome withholds SameSite=Strict cookies
				// for an entire cross-site-initiated redirect chain, and did
				// so here while the cookie was still Strict -- turns that
				// into an infinite 303 loop (ERR_TOO_MANY_REDIRECTS on
				// /unmask/admin/, tool1-jp 2026-07-10).  A POST in this state
				// still 403s: its form was rendered under the old, expired
				// token (= the operator reloads, picks up the cookie, retries).
				if CSRFTokenFromRequest(r) == "" {
					if tok, terr := newCSRFToken(); terr == nil {
						http.SetCookie(w, issueCSRFCookie(tok, secure, pay.Remember))
						if r.Method == http.MethodGet || r.Method == http.MethodHead {
							r = withIssuedCSRFToken(r, tok)
						}
					}
				}
				// CSRF: every state-changing method that flows through
				// AuthMiddleware (= POST / PUT / PATCH / DELETE) must
				// carry a token matching the cookie.  GET / HEAD /
				// OPTIONS pass through untouched -- they don't mutate
				// state; the protection is the double-submit echo (a
				// hidden field cross-origin JS cannot read), not the
				// cookie's SameSite mode (Lax, matching the session).
				if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
					if err := r.ParseForm(); err != nil {
						http.Error(w, "form parse error", http.StatusBadRequest)
						return
					}
					if !verifyCSRF(r) {
						if strings.HasPrefix(r.URL.Path, h.cfg().Server.BasePath+"/admin/api/") {
							writeJSON(w, http.StatusForbidden, map[string]any{"ok": 0, "error": "csrf"})
							return
						}
						http.Error(w, "csrf token mismatch (= reload the page and retry)", http.StatusForbidden)
						return
					}
				}
				ctx := context.WithValue(r.Context(), sessionCtxKey{}, pay)
				next(w, r.WithContext(ctx))
				return
			}
		}
		// failure
		if strings.HasPrefix(r.URL.Path, h.cfg().Server.BasePath+"/admin/api/") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": 0, "error": "unauthorized"})
			return
		}
		ret := r.URL.Path
		if r.URL.RawQuery != "" {
			ret += "?" + r.URL.RawQuery
		}
		dst := h.cfg().Server.BasePath + "/admin/login?return=" + url.QueryEscape(ret)
		http.Redirect(w, r, dst, http.StatusFound)
	}
}

// RequireRole is middleware that returns 403 unless the session role >= min.
//   - "superadmin" : superadmin only
//   - "admin"      : admin / superadmin
//   - "viewer"     : anyone authenticated
//
// Used after AuthMiddleware.  Reads SessionPayload out of the context and checks.
func (h *Handler) RequireRole(min string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pay := SessionFromContext(r)
		if pay == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !roleAtLeast(pay.Role, min) {
			http.Error(w, "forbidden (insufficient role)", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// roleAtLeast reports whether role >= min.  superadmin > admin > viewer.
func roleAtLeast(role, min string) bool {
	rank := map[string]int{"viewer": 1, "admin": 2, "superadmin": 3}
	rMin, ok := rank[min]
	if !ok {
		// An unknown/empty min must DENY, not allow everyone: rank[""]==0 would
		// otherwise make every role "at least" it.  Current callers all pass a
		// real role, so this is defense-in-depth against a future miswire.
		return false
	}
	return rank[role] >= rMin
}

// flashCookiePrefix is the prefix for flash cookies ("unmask_flash_<key>").
// Avoids putting long messages in the query string; passed via a short-lived
// cookie and consumed on the next GET.
const flashCookiePrefix = "unmask_flash_"

// setFlash writes a flash message to a cookie just before a redirect.  Expires
// after 60 seconds (safety net for cases where the next GET never happens;
// normally readFlash deletes it on the next GET).
func setFlash(w http.ResponseWriter, r *http.Request, basePath, key, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookiePrefix + key,
		Value:    url.QueryEscape(msg),
		Path:     basePath + "/admin/",
		MaxAge:   60,
		HttpOnly: false,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

// readFlash extracts the message from the cookie and **immediately deletes it**
// (shown once).  Returns "" if missing / unreadable.
func readFlash(w http.ResponseWriter, r *http.Request, basePath, key string) string {
	c, err := r.Cookie(flashCookiePrefix + key)
	if err != nil {
		return ""
	}
	// Issue a deletion cookie (MaxAge=-1).
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookiePrefix + key,
		Value:    "",
		Path:     basePath + "/admin/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
	v, err := url.QueryUnescape(c.Value)
	if err != nil {
		return ""
	}
	return v
}

// AdminIPAllowMiddleware enforces both remote-IP and Host-header access
// control on /admin/*.
//
// Configuration:
//   - settings.Nginx.AdminAllowedIPs — IP / CIDR list (e.g. "192.168.0.0/24").
//   - settings.Nginx.AdminAllowedHosts — Host-header list (e.g. "admin.example.com").
//   - Either list empty = allow all.  That IS the shipped default: the install
//     wizard deliberately does not write AdminAllowedIPs (an auto-guessed CIDR
//     would lock a roaming operator out of the very UI needed to fix it, with
//     config.yml editing as the only recovery), so until the operator fills it
//     in under settings → nginx, the admin UI is gated by login + CSRF + the
//     per-IP login rate-limit only.  AdminAllowedHosts is opt-in for the
//     "single nginx serves many domains but only one should expose the admin
//     UI" pattern.
//
// The rendered nginx server.conf emits the equivalent IP allow / deny, but
// existing integrated deployments that don't include the rendered conf
// won't see it.  Enforcing this at the handler layer guarantees a consistent
// restriction independent of nginx config.  The Host check is handler-only
// (= nginx still proxies every /unmask/* path; the admin decides what to
// expose).
//
// Not applied during the install wizard (/admin/setup/) so the initial install
// can't lock you out before any IP / Host is configured.  Applied to
// /admin/login to prevent brute force from unauthorized IPs.
func (h *Handler) AdminIPAllowMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Bypass during the install wizard (setup token guards it separately).
		if needed, _ := h.SetupNeeded(r); needed {
			next(w, r)
			return
		}
		ip := adminClientIP(r, h.snapshotSettings())
		if allowIPs := settings.EnabledValues(h.cfg().Nginx.AdminAllowedIPs, h.cfg().Nginx.AdminAllowedIPsDisabled); !ipAllowed(ip, allowIPs) {
			log.Printf("admin IP denied: ip=%s path=%s allow_from=%v", ip, r.URL.Path, allowIPs)
			adminIPForbidden(w, ip)
			return
		}
		host := adminClientHost(r, h.snapshotSettings())
		if allowHosts := settings.EnabledValues(h.cfg().Nginx.AdminAllowedHosts, h.cfg().Nginx.AdminAllowedHostsDisabled); !hostAllowed(host, allowHosts) {
			log.Printf("admin host denied: host=%s path=%s allowed_hosts=%v", host, r.URL.Path, allowHosts)
			adminHostForbidden(w, host)
			return
		}
		// Login and password-reset attempts are audited before any session
		// exists, and a failed login is precisely the row whose origin matters.
		next(w, r.WithContext(user.WithClientIP(r.Context(), ip)))
	}
}

// adminIPForbidden / adminHostForbidden write a 403 with an operator hint: the
// offending IP/Host (which the caller already knows about itself) + how to fix a
// self-lockout.  Deliberately does NOT reveal the allowed list -- that would tell
// an unauthorized visitor which IPs / Hosts are trusted.
func adminIPForbidden(w http.ResponseWriter, ip string) {
	http.Error(w, "Forbidden: your IP ("+ip+") is not allowed to reach the admin UI.\n"+
		"If you locked yourself out, add this IP/CIDR to admin_allowed_ips in /etc/unmask/config.yml and "+
		"restart unmask -- or edit it under Settings -> Network from an already-allowed IP.", http.StatusForbidden)
}

func adminHostForbidden(w http.ResponseWriter, host string) {
	http.Error(w, "Forbidden: this Host ("+host+") is not allowed to reach the admin UI.\n"+
		"If you locked yourself out, add this Host to admin_allowed_hosts in /etc/unmask/config.yml and "+
		"restart unmask -- or edit it under Settings -> Network from an already-allowed Host.", http.StatusForbidden)
}

// ruleRowSt is what ruleRowState hands a rule-list template for one row:
// Class is the space-prefixed extra classes for the row div (" editing",
// " rule-row-error"), Err says whether to print the inline message beneath it.
type ruleRowSt struct {
	Class   string
	Err     bool
	editing bool
}

// hostAllowed reports whether the Host header matches any entry in allowList.
// Comparison is case-insensitive and any trailing port (= ":443" etc.) is
// stripped before matching.  Empty allowList means allow all (= the default;
// avoids lockout from misconfiguration on first install).
//
// IPv6 literals come in as "[::1]:443" / "[::1]" — strip ":port" only when
// the host isn't already bracketed at the end.
func hostAllowed(host string, allowList []string) bool {
	if len(allowList) == 0 {
		return true
	}
	host = strings.TrimSpace(host)
	// Strip the trailing port if present.  For an IPv6 "[::1]:443" host the
	// port lives after the closing ']'.  For "[::1]" alone there is no port.
	if strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, "]"); i > 0 {
			if i+1 < len(host) && host[i+1] == ':' {
				host = host[:i+1]
			}
		}
	} else if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	for _, entry := range allowList {
		if hostMatchesPattern(host, strings.TrimSpace(entry)) {
			return true
		}
	}
	return false
}

// hostMatchesPattern matches one allowlist entry against an already-normalised
// (lower-cased, port-stripped) host, honouring the same exact/contains/regex
// convention the rest of the settings lists use (settings.PatternModeOf): a
// bare value is a regex, "exact:" and "contains:" change the reading.  The
// widget that edits this field shows a mode toggle, so an entry saved as a
// regex has to be read as one here -- until this existed the toggle was inert
// and only a plain literal ever matched.
//
// The one deliberate difference from the shared convention: a regex here is
// FULLY ANCHORED.  Everywhere else the lists are challenge / deny targets,
// where matching more traffic only means more scrutiny; this list is an ALLOW
// list guarding the admin UI, where matching more means granting more access.
// An unanchored "tool\d+-[a-z]+" would admit "tool1-jp.attacker.com"; anchored,
// it admits exactly the hostnames it spells out.
func hostMatchesPattern(host, entry string) bool {
	if entry == "" {
		return false
	}
	switch settings.PatternModeOf(entry) {
	case settings.ModeExact, settings.ModeContains:
		// Exact host.  A legacy "contains:" entry is read as exact rather than
		// substring: the UI no longer offers contains here because a substring
		// match on an allowlist admits uic.jp.attacker.com, so we fail closed.
		return strings.EqualFold(host, settings.PatternText(entry))
	case settings.ModeSubdomain:
		// The host itself or any subdomain of it, anchored: example.com matches
		// example.com and x.example.com, never example.com.attacker.com.
		d := strings.ToLower(settings.PatternText(entry))
		h := strings.ToLower(host)
		return h == d || strings.HasSuffix(h, "."+d)
	default: // regex
		re, err := regexp.Compile("(?i)^(?:" + entry + ")$")
		if err != nil {
			// A pattern that does not compile matches nothing -- an allow list
			// fails closed.  Save-time validation rejects these, so a stored
			// one is only reachable via a hand-edited config.
			return false
		}
		return re.MatchString(host)
	}
}

// ipAllowed reports whether ip matches any entry in allowList.  Supports both
// exact and CIDR.  Empty allowList means allow all (= the default; avoids
// lockout from misconfiguration on first install).
func ipAllowed(ip string, allowList []string) bool {
	if len(allowList) == 0 {
		return true
	}
	// A unix-socket connection has no IP, so adminClientIP resolves to "" (a
	// socket peer isn't a trusted proxy, so X-Real-IP isn't trusted either).
	// Honor an explicit allow-all (/0) list for that EMPTY peer, so socket-mode
	// admin doesn't 403 despite an "allow all" list.  Only "" is waived here --
	// a genuinely invalid IP like "zzz" must still be rejected below, and a
	// non-/0 list still rejects "" (a specific-IP allowlist can't be satisfied
	// over a socket; use the socket file's 0660 group for that instead).
	if ip == "" && adminIPsAllowAll(allowList) {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range allowList {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// CIDR (contains "/") uses ParseCIDR.  Exact IP uses ParseIP.
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err == nil && cidr.Contains(parsed) {
				return true
			}
			continue
		}
		if e := net.ParseIP(entry); e != nil && e.Equal(parsed) {
			return true
		}
	}
	return false
}

// addMeToData injects the common header data used by every admin page render:
// "Me" / "MeName" / "BasePath" / "CSRFToken" (consumed by the user_menu partial
// and every POST form) plus the host / site picker data consumed by the
// header_tools partial.  When unauthenticated (e.g. login page) Me / MeName
// are skipped; BasePath / CSRFToken / picker data are always set.
func (h *Handler) addMeToData(r *http.Request, data map[string]any) {
	if _, ok := data["BasePath"]; !ok {
		data["BasePath"] = h.cfg().Server.BasePath
	}
	if _, ok := data["CSRFToken"]; !ok {
		data["CSRFToken"] = CSRFTokenFromRequest(r)
	}
	if pay := SessionFromContext(r); pay != nil {
		data["Me"] = pay
		if h.UserRepo != nil {
			if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
				data["MeName"] = u.Username
			}
		}
	}
	// "共有 BAN" tab badge: count of source=community_bans rows in BanMgr so
	// auto-applied entries don't go unnoticed across multiple sessions.
	// Cheap: the live snapshot is already in memory.  0 = no badge.
	if _, ok := data["NavCommunityBadge"]; !ok {
		// Always set an int.  The nav partial runs `gt .NavCommunityBadge 0` on
		// every admin page; a missing key makes that comparison error and abort
		// the whole template mid-render (= silent 200 truncation).  BanMgr nil
		// simply means a count of 0.
		n := 0
		if h.BanMgr != nil {
			for _, e := range h.BanMgr.Snapshot() {
				if e.Source == "community_bans" {
					n++
				}
			}
		}
		data["NavCommunityBadge"] = n
	}

	// Host + site picker data for the shared header_tools partial (= the
	// host / site filter pickers, rendered on every admin page).  Each key is
	// guarded independently so a handler that pre-set one (e.g. the settings
	// page sets Sites for a datalist, and SelfHostID) still gets the rest —
	// otherwise the picker template hits an undefined .SiteSelected and the
	// whole page render fails.  Hosts = observed host ids; HostSelected = the
	// unmask_hosts narrowing; Sites = observed sites; SiteSelected = the
	// single unmask_site narrowing ("" = all).
	if _, ok := data["Hosts"]; !ok {
		hostList, _ := events.DistinctHosts(r.Context(), h.DB)
		if h.HostID != "" {
			seen := false
			for _, x := range hostList {
				if x == h.HostID {
					seen = true
					break
				}
			}
			if !seen {
				hostList = append([]string{h.HostID}, hostList...)
			}
		}
		// Disabled hosts (= retired / mis-configured instances) drop out of the
		// picker; they remain in the DB and in the host inventory table.
		if dis := h.cfg().Hosts.Disabled; len(dis) > 0 {
			disSet := make(map[string]bool, len(dis))
			for _, d := range dis {
				disSet[d] = true
			}
			kept := make([]string, 0, len(hostList))
			for _, x := range hostList {
				if !disSet[x] {
					kept = append(kept, x)
				}
			}
			hostList = kept
		}
		data["Hosts"] = hostList
	}
	if _, ok := data["HostSelected"]; !ok {
		list := resolveHostFilter(r)
		sel := map[string]bool{}
		for _, x := range list {
			sel[x] = true
		}
		data["HostSelected"] = sel
		// HostSelectedList: the same selection as a slice, so the picker
		// summary can show the single host's name when exactly one is picked.
		data["HostSelectedList"] = list
	}
	if _, ok := data["SelfHostID"]; !ok {
		data["SelfHostID"] = h.HostID
	}
	// site picker options.  In "defined" acceptance mode the picker lists only
	// the defined sites — a ghost (= an undefined Host, possibly spoofed) must
	// not pollute the dropdown.  In "auto" mode every observed site is listed.
	// A site currently selected via cookie but absent from the list is still
	// shown as an extra option (so the dropdown matches the active filter),
	// flagged as a ghost when in defined mode.
	{
		definedMode := h.cfg().Sites.ResolvedMode() == settings.SiteModeDefined
		var opts []string
		if definedMode {
			opts = append(opts, h.cfg().Sites.ActiveDefined()...)
		} else {
			opts, _ = events.DistinctSites(r.Context(), h.DB)
		}
		sel := resolveSiteFilter(r)
		inList := false
		for _, s := range opts {
			if s == sel {
				inList = true
				break
			}
		}
		data["SitePickerOptions"] = opts
		data["SiteSelected"] = sel
		data["SiteSelectedExtra"] = sel != "" && !inList
		data["SiteSelectedGhost"] = sel != "" && !inList && definedMode
	}
}

// AdminLoginGet: GET {base}/admin/login — render the login form.
func (h *Handler) AdminLoginGet(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Lang":        i18n.Resolve(r),
		"BasePath":    h.cfg().Server.BasePath,
		"Return":      r.URL.Query().Get("return"),
		"Error":       r.URL.Query().Get("err"),
		"MailEnabled": h.Mailer != nil && h.Mailer.Enabled(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("login render: %v", err)
	}
}

// AdminLoginPost: POST {base}/admin/login — verify username + password, set cookie, then redirect.
func (h *Handler) AdminLoginPost(w http.ResponseWriter, r *http.Request) {
	base := h.cfg().Server.BasePath
	ret := r.FormValue("return")
	// Must be a local path (not "//" / "/\" = a protocol-relative off-site URL).
	if !isLocalRedirect(ret) {
		ret = base + "/admin/"
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// Per-IP lockout: the app's own brute-force guard (see loginThrottle --
	// the rate-limit zone that used to stand here never fired for clients
	// holding a _bv cookie, which is everyone the protected path lets
	// through).  Checked before touching the user store so a locked address
	// cannot keep burning argon2 time either.
	ip := adminClientIP(r, *h.cfg())
	now := time.Now()
	if d := h.throttle().lockedFor(loginKey(ip), now); d > 0 {
		tooManyLoginAttempts(w, d)
		return
	}

	rejectInvalid := func() {
		// audit best-effort
		if h.UserRepo != nil {
			h.UserRepo.Record(r.Context(), 0, username, "login_failed", "", "")
		}
		t := h.throttle()
		if d := t.note(loginKey(ip), now, t.failLimit, t.failWindow, t.lockFor); d > 0 {
			if h.UserRepo != nil {
				h.UserRepo.Record(r.Context(), 0, username, "login_locked", "", ip)
			}
			tooManyLoginAttempts(w, d)
			return
		}
		dst := base + "/admin/login?err=invalid&return=" + url.QueryEscape(ret)
		http.Redirect(w, r, dst, http.StatusFound)
	}

	if username == "" || password == "" || h.UserRepo == nil {
		rejectInvalid()
		return
	}
	u, err := h.UserRepo.GetByUsername(r.Context(), username)
	if err != nil {
		// Equalize timing: a non-existent username must cost the same as a real
		// one (which runs argon2id below) so response time can't enumerate users.
		user.DummyCheckPassword(password)
		rejectInvalid()
		return
	}
	if err := user.CheckPassword(u.PasswordHash, password); err != nil {
		rejectInvalid()
		return
	}
	if u.Disabled {
		// Correct password, suspended account.  Same rejection as a wrong
		// password, and checked AFTER the argon2 run: a distinct message or a
		// pre-hash return would confirm the account exists and is suspended.
		rejectInvalid()
		return
	}
	// Transparently upgrade the stored hash if the argon2 cost parameters have
	// been raised since it was written (AUTH-6).  Best-effort: a failure here
	// must not block an otherwise-valid login.
	if user.NeedsRehash(u.PasswordHash) {
		if err := h.UserRepo.SetPassword(r.Context(), u.ID, password); err != nil {
			log.Printf("password rehash on login (user %d): %v", u.ID, err)
		}
	}
	h.throttle().clear(loginKey(ip)) // a successful login is a clean slate
	h.UserRepo.TouchLastLogin(r.Context(), u.ID)
	h.UserRepo.Record(r.Context(), u.ID, u.Username, "login", "", "")
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	remember := r.FormValue("remember") != ""
	http.SetCookie(w, issueSessionCookie(h.cfg().Secret.BVSecret, u.ID, u.Role, secure, remember))
	// Pair the session with a fresh CSRF token (= double-submit cookie).
	// A token failure here is logged but not fatal: an operator can
	// still navigate to GET pages, and the templates' AuthMiddleware
	// path will issue one on the next request.
	if tok, err := newCSRFToken(); err == nil {
		http.SetCookie(w, issueCSRFCookie(tok, secure, remember))
	} else {
		log.Printf("csrf token generate: %v", err)
	}
	http.Redirect(w, r, ret, http.StatusFound)
}

// AdminLogout: POST or GET {base}/admin/logout — invalidate the session cookie.
func (h *Handler) AdminLogout(w http.ResponseWriter, r *http.Request) {
	if pay := SessionFromContext(r); pay != nil && h.UserRepo != nil {
		username := ""
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			username = u.Username
		}
		h.UserRepo.Record(r.Context(), pay.UserID, username, "logout", "", "")
	}
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, clearSessionCookie(secure))
	http.SetCookie(w, clearCSRFCookie(secure))
	http.Redirect(w, r, h.cfg().Server.BasePath+"/admin/login", http.StatusFound)
}

// docs are consolidated at unmask.sh/docs/, so the in-admin docs handler
// (AdminDocs) is removed.  The router (main.go) 302-redirects /admin/docs/
// to https://unmask.sh/docs/.

// AdminSiteList: GET {base}/admin/  — list observed sites, or if site<=1, jump
// straight into that site's dashboard (URL stays /admin/).
//
// Most deployments have only the default site, so the intermediate "site list"
// is unnecessary; internally dispatch directly to the dashboard.  ?list=1
// forces the list view (useful for verifying once more sites are added).
func (h *Handler) AdminSiteList(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng != "7d" && rng != "30d" {
		rng = "24h"
	}
	hours := dashboard.RangeHours(rng)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sites, err := dashboard.Sites(ctx, h.DB, hours)
	// Site list is informational on this entry handler.  When the listing
	// query times out (= 30d range on a large operator DB), still hand off
	// to renderStats with the default site so the page is not blocked
	// behind it.  list=1 is the only path that actually depends on the site
	// summary rows, so keep its strict error there.
	if err != nil {
		log.Printf("sites: %v", err)
		if r.URL.Query().Get("list") == "1" {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		h.renderStats(w, r, defaultSite)
		return
	}
	// site <= 1 -> internally dispatch and render the dashboard directly.  list=1 forces the list.
	if r.URL.Query().Get("list") != "1" {
		target := defaultSite
		if len(sites) == 1 {
			target = sites[0].Site
		}
		h.renderStats(w, r, target)
		return
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	loc := resolveLocation(r)
	dashboard.ApplyDisplayLoc(sites, loc)
	now := time.Now()
	rangeStart := now.Add(-time.Duration(hours) * time.Hour)
	data := map[string]any{
		"Lang":  i18n.Resolve(r),
		"TZ":    resolveTZ(r),
		"Range": rng,
		// RangeStartTS = epoch sec UTC.  Emit in the template as <time class="js-datetime"
		// data-ts="...">; JS reformats in the browser TZ.
		"RangeStartTS":       rangeStart.Unix(),
		"RangeStartFallback": rangeStart.In(loc).Format("2006-01-02 15:04 MST"),
		"Sites":              sites,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "site_list.html", data); err != nil {
		log.Printf("site list render: %v", err)
	}
}

// AdminStats: GET {base}/admin/stats/{site}/ — the per-site stats page (the
// charts / per-card breakdowns).  Named for its route: the "dashboard" it was
// called before is the landing overview (AdminTopOverview, /admin/), a
// different page — the mismatch caused repeated confusion.
func (h *Handler) AdminStats(w http.ResponseWriter, r *http.Request) {
	site, ok := pickSite(r)
	if !ok {
		http.Error(w, "invalid site id", http.StatusBadRequest)
		return
	}
	h.renderStats(w, r, site)
}

// dashboardHosts resolves the stats-dashboard host filter, collapsing a
// non-narrowing selection to nil. The shared host_picker often holds "all
// hosts" as the explicit full list — on a single-host install, that one host —
// which filters nothing. The aggregate fast paths have no host dimension and
// engage only when hosts is empty, so a non-narrowing selection must collapse
// or the default view always falls back to the slow raw scan.
func (h *Handler) dashboardHosts(r *http.Request) []string {
	hosts := resolveHostFilter(r)
	if len(hosts) == 0 {
		return nil
	}
	all, err := events.DistinctHosts(r.Context(), h.DB)
	if err != nil || len(all) == 0 {
		return hosts
	}
	// A disabled host is dropped by the raw-scan path (hostCond) but not by the
	// aggregate (no host dimension). A disabled host that still has events thus
	// forbids the collapse — but a stale disabled entry whose host has no events
	// is harmless (nothing for the two paths to disagree on).
	disabled := map[string]bool{}
	for _, d := range h.cfg().Hosts.Disabled {
		disabled[d] = true
	}
	sel := make(map[string]bool, len(hosts))
	for _, x := range hosts {
		sel[x] = true
	}
	for _, x := range all {
		if disabled[x] {
			return hosts // a disabled host has events → agg / scan would differ
		}
		if !sel[x] {
			return hosts // a known host is unselected → genuine narrowing
		}
	}
	return nil // every host with events is selected and enabled → not a real filter
}

// renderStats renders the stats template for the result of pickSite.  Called
// by both AdminStats (/admin/stats/{site}/) and AdminSiteList (/admin/stats/
// when site<=1).
func (h *Handler) renderStats(w http.ResponseWriter, r *http.Request, site string) {
	// The stats page scopes by the shared site_picker (single-select), not by
	// the legacy /admin/stats/{site}/ path segment.  cookie / ?site=; "" = all sites.
	site = resolveSiteFilter(r)
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		log.Printf("dashboard tmpl load: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	rng := r.URL.Query().Get("range")
	switch rng {
	case "7d", "30d", "90d", "180d", "365d", "all", "custom":
		// valid
	default:
		rng = "24h"
	}
	hours := dashboard.RangeHours(rng) // "all"/"custom" resolve via the ctx window below
	nowTime := time.Now()
	// How far back this page can honestly look is the SHORTER of its two
	// sources.  The summary figures and the per-day series come from the hourly
	// aggregate, pruned on a fixed window that deliberately does not follow
	// events_retention_days; the funnel / country / flag cards come from raw
	// events, which does.  Gating the picker on raw age alone offered ranges
	// the aggregates could not fill: on an install keeping 90 days of events,
	// "90d" appeared and the totals under it were a month of data wearing a
	// quarter's label, with nothing on screen to say so.
	//
	// Timestamps run the other way from history: the LATER of the two oldest
	// marks is the SHORTER reach.  Either source missing entirely means the
	// page cannot fill a long window at all, so it offers none.
	oldestEventTS, _ := dashboard.OldestEventTS(r.Context(), h.DB)
	oldestAggTS, _ := dashboard.OldestAggregateTS(r.Context(), h.DB)
	oldestTS := int64(0)
	if oldestEventTS > 0 && oldestAggTS > 0 {
		oldestTS = oldestEventTS
		if oldestAggTS > oldestTS {
			oldestTS = oldestAggTS
		}
	}
	// custom range: from/to are operator-TZ calendar dates (YYYY-MM-DD), resolved
	// to a UTC [00:00 from, 23:59:59 to] window.  "all" spans [the bound above,
	// now] -- the oldest point both sources reach, not the oldest event.
	// An invalid custom range KEEPS rng="custom" (so the picker still renders,
	// pre-filled) but leaves the window unset, so the queries fall back to the 24h
	// span until the operator picks valid dates.
	var customFromTS, customToTS int64
	customValid := false
	switch rng {
	case "custom":
		customFromTS, customToTS = parseCustomRange(r.URL.Query().Get("from"), r.URL.Query().Get("to"), resolveLocation(r))
		customValid = customFromTS > 0 && customToTS > customFromTS
	case "all":
		customFromTS, customToTS = oldestTS, nowTime.Unix()
		customValid = oldestTS > 0 && customToTS > customFromTS
	}
	win := dashboard.WindowFromRange(rng, nowTime, customFromTS, customToTS)
	// Range-bar presets, widened to the data actually on hand: the long presets
	// only appear once BOTH sources have enough history behind them, and "all"
	// once there's more than the 30d default.  With the aggregate window fixed
	// well under a quarter, that means 90d and beyond stay hidden until the
	// aggregates themselves reach back that far -- the page does not offer a
	// span it would have to pad.  See DataMinDate for the calendar bound.
	rangePresets := []string{"24h", "7d", "30d"}
	if oldestTS > 0 {
		availDays := (nowTime.Unix() - oldestTS) / 86400
		if availDays > 30 {
			rangePresets = append(rangePresets, "90d")
		}
		if availDays > 90 {
			rangePresets = append(rangePresets, "180d")
		}
		if availDays > 180 {
			rangePresets = append(rangePresets, "365d")
		}
		if availDays > 30 {
			rangePresets = append(rangePresets, "all")
		}
	}

	// host filter (global scope of the shared host_picker; sourced from
	// cookie / ?host=).  Passed to every dashboard query (unmask_event-based
	// queries narrow with host IN(...); cookie traversal / 30-day trend (1)
	// are based on cookie_minute which has no host column, so they don't apply).
	// dashboardHosts collapses a non-narrowing "all hosts" selection to nil so
	// the aggregate fast paths still engage.
	hosts := h.dashboardHosts(r)

	// Overall dashboard timeout (each query carries its own shorter ctx deadline).
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	// A custom range overrides the trailing-`hours` window every dashboard query
	// would otherwise compute from now.  Presets leave ctx unset so the queries
	// fall back to their `hours` arg and behave exactly as before.
	if (rng == "custom" || rng == "all") && customValid {
		ctx = dashboard.WithWindow(ctx, win)
	}

	// Helper to compose a per-query timeout.  Assigns heavy queries (e.g. the
	// 30-day aggregate) their own ctx so an upstream slow query doesn't cascade.
	queryCtx := func(d time.Duration) (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, d)
	}

	// Collect verdict names judged "action=bot or suspect" by the settings.
	// Used by the SQL stealth count + classify bot judgment.
	botVerdicts := dashboard.BotVerdictNames(h.cfg().Nginx)

	// Reverse map: verdict name -> action ("bot" / "suspect" / "ok").  Used by
	// the template for badge judgment.  Combines preset rules + Extra rules.
	// Intentionally has no prefix "bot_*" judgment or compat alias (the
	// settings.Action enum is the source of truth).
	verdictAction := map[string]string{}
	for _, g := range nginxconf.JA4VerdictGroups {
		for _, rule := range g.Rules {
			verdictAction[rule.Verdict] = rule.Action
		}
	}
	for _, p := range h.cfg().Nginx.JA4Verdicts.Extra {
		verdictAction[p.Verdict] = p.Action
	}

	// Operator cookie TZ -> *time.Location for the day-bucketed queries.
	// Storage is UTC; day boundaries (and only those) are converted here so
	// the chart's labels follow the operator.
	loc := resolveLocation(r)

	// Each dashboard card is an independent read query.  Previously executed
	// sequentially, so the whole page latency was queries x per-query latency,
	// degrading linearly as the event table grew.  Run them in parallel using
	// WAL + conn pool.  A semaphore caps concurrency at 6, leaving conn pool
	// headroom (max 8) for challenge writes.
	var (
		funnel                  []dashboard.FunnelRow
		funnelErr               error
		cookieRows              []dashboard.CookieStatusRow
		rlSummary               dashboard.RLSummary
		rlIPs                   []dashboard.RLIPRow
		rlPaths                 []dashboard.RLPathRow
		rlPathQueries           map[string][]dashboard.RLQueryCount
		flagsRows               []dashboard.FlagsRow
		verdictDist             []dashboard.VerdictCount
		hitRows                 []dashboard.CaptchaForceRow
		loopRows                []dashboard.ReloadLoopRow
		verifyNG                []dashboard.VerifyNGRow
		cookieFails             []dashboard.CookieFailRow
		stealth                 []dashboard.StealthRow
		jsErrs                  []dashboard.JSErrorRow
		jsForeign               []dashboard.JSErrorRow
		jsForeignCount          int
		cpVerdictCounts         map[string]int
		cpForceReasonCounts     map[string]int
		cpFailForceReasonCounts map[string]int
		cpTopIPs                []dashboard.CaptchaPassIPRow
		cpRecent                []dashboard.CaptchaPassRow
		cpReuse                 []dashboard.CookieReuseRow
		powReuse                []dashboard.CookieReuseRow
		rebindReuse             []dashboard.CookieReuseRow
		rebindLineages          []events.RebindLineageRow
		aiTraffic               []dashboard.AITrafficRow
		aiTrafficAll            []AITrafficRow
		aiTrafficDetail         map[string][]AICrawlerRow
		dailyKind               []dashboard.DailyKindBucket
		dailyTotal              []dashboard.DailyTotal
		dailyServeKind          []dashboard.DailyKindBucket
		dailyServeTotal         []dashboard.DailyTotal
		countries               []dashboard.CountryRow
		dailyCountry            []dashboard.DailyCountryBucket
		dailyUniq               []dashboard.DailyUniq
	)
	qStart := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	var cardMu sync.Mutex
	var failedCards []string
	markFailed := func(name string) {
		cardMu.Lock()
		failedCards = append(failedCards, name)
		cardMu.Unlock()
	}
	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A panic in a card query (bad DB row, nil deref) would otherwise
			// crash the whole daemon -- net/http does not recover goroutines the
			// handler spawns.  Recover so one bad card can't take the site down,
			// and mark it failed (= the dashboard shows a "data incomplete"
			// banner instead of a silently-empty card the operator reads as 0).
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("stats card %s PANIC: %v", name, rec)
					markFailed(name)
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()
			t0 := time.Now()
			if err := fn(); err != nil {
				log.Printf("stats card %s failed: %v", name, err)
				markFailed(name)
			}
			if elapsed := time.Since(t0); elapsed > 200*time.Millisecond {
				log.Printf("stats card %s: %v elapsed", name, elapsed)
			}
		}()
	}
	run("funnel", func() error {
		fctx, fcancel := queryCtx(5 * time.Second)
		defer fcancel()
		funnel, funnelErr = dashboard.Funnel(fctx, h.DB, site, hosts, hours, botVerdicts, h.VerdictRegistry(), site != "" && h.cfg().Sites.DefinedSet()[site])
		return funnelErr
	})
	run("CookieStatus", func() error {
		var e error
		cookieRows, e = dashboard.CookieStatus(ctx, h.DB, site, hosts, hours)
		return e
	})
	// Pre-gate the rate-limit cards on the aggregate's serve-rl count.  On
	// any operator install where rate_limit is rare (= the common case),
	// this skips four 80k-row raw scans worth of dashboard latency per page
	// load.  When the aggregate isn't ready or the page is site/host
	// filtered, HasRateLimited conservatively returns true so the raw cards
	// still render.
	hasRL, _ := dashboard.HasRateLimited(ctx, h.DB, site, hosts, hours)
	if hasRL {
		// One card, one pass: RateLimitAll scans the rl=1 serve window once and
		// aggregates all four breakdowns, instead of four cards each re-scanning
		// it (4x the I/O + page-cache contention on a large cold DB).
		run("RateLimitAll", func() error {
			var e error
			rlSummary, rlIPs, rlPaths, rlPathQueries, e = dashboard.RateLimitAll(ctx, h.DB, site, hosts, hours, 30, 30, 5)
			return e
		})
	}
	run("FlagsDistribution", func() error {
		var e error
		flagsRows, e = dashboard.FlagsDistribution(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("VerdictDistribution", func() error {
		var e error
		verdictDist, e = dashboard.VerdictDistribution(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("CaptchaForceBreakdown", func() error {
		var e error
		hitRows, e = dashboard.CaptchaForceBreakdown(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("ReloadLoops", func() error {
		var e error
		loopRows, e = dashboard.ReloadLoops(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("VerifyNGRanking", func() error {
		var e error
		verifyNG, e = dashboard.VerifyNGRanking(ctx, h.DB, site, hosts, hours, 30)
		return e
	})
	run("CookieSetFails", func() error {
		var e error
		cookieFails, e = dashboard.CookieSetFails(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("StealthPassed", func() error {
		var e error
		stealth, e = dashboard.StealthPassed(ctx, h.DB, site, hosts, hours, botVerdicts)
		return e
	})
	run("JSErrors", func() error { var e error; jsErrs, e = dashboard.JSErrors(ctx, h.DB, site, hosts, hours); return e })
	run("JSForeignErrors", func() error {
		var e error
		jsForeign, e = dashboard.JSForeignErrors(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("JSForeignErrorCount", func() error {
		var e error
		jsForeignCount, e = dashboard.JSForeignErrorCount(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("CaptchaPassVerdicts", func() error {
		var e error
		cpVerdictCounts, e = dashboard.CaptchaPassVerdictCounts(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("CaptchaPassForceReasons", func() error {
		var e error
		cpForceReasonCounts, e = dashboard.CaptchaPassForceReasonCounts(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("CaptchaFailForceReasons", func() error {
		var e error
		cpFailForceReasonCounts, e = dashboard.CaptchaFailForceReasonCounts(ctx, h.DB, site, hosts, hours)
		return e
	})
	run("CaptchaPassTopIPs", func() error {
		var e error
		cpTopIPs, e = dashboard.CaptchaPassTopIPs(ctx, h.DB, site, hosts, hours, 30)
		return e
	})
	run("CaptchaPassRecent", func() error {
		var e error
		cpRecent, e = dashboard.CaptchaPassRecent(ctx, h.DB, site, hosts, hours, 10)
		return e
	})
	run("CaptchaReuse", func() error {
		var e error
		cpReuse, e = dashboard.CookieReuseTopIPs(ctx, h.DB, site, "captcha", hosts, hours, 30)
		return e
	})
	// Lineage travel: one solve, and how many addresses it has been carried
	// to.  Sits with the reuse rankings because it is the same question along
	// the other axis -- they are read together or not at all.  30 rows to
	// match the rankings beside it: ten shown, the rest behind "show more".
	run("RebindLineages", func() error {
		var e error
		rebindLineages, e = events.RankByRebindLineage(ctx, h.DB, hours*60, 30)
		return e
	})
	run("RebindReuse", func() error {
		var e error
		rebindReuse, e = dashboard.CookieReuseTopIPs(ctx, h.DB, site, "rebind", hosts, hours, 30)
		return e
	})
	run("PowReuse", func() error {
		var e error
		powReuse, e = dashboard.CookieReuseTopIPs(ctx, h.DB, site, "pow", hosts, hours, 30)
		return e
	})
	run("AITrafficBreakdown", func() error {
		var e error
		aiTraffic, e = dashboard.AITrafficBreakdown(ctx, h.DB, site, hosts, hours)
		return e
	})
	// All-traffic view (= access-log pipeline, includes rescued/bypassed
	// crawlers).  unmask_crawler_minute is install-wide; the site filter
	// doesn't narrow it, but we still expose the data so the stats card
	// can show the "all" tab alongside the site-scoped "served" view.
	// return ctx.Err() (not nil): aiTrafficSummary / aiTrafficDrilldown swallow
	// their query error internally and just yield zero rows, so without this a
	// deadline-exceeded would leave the AI card silently empty instead of
	// joining the FailedCards banner like every other card on this dashboard.
	run("AITrafficAll", func() error { aiTrafficAll = aiTrafficSummary(ctx, h, hours*60); return ctx.Err() })
	// Per-crawler drill-down for the "all" tab's popover (= same window as
	// AITrafficAll, resolved category -> individual crawler).
	run("AITrafficDetail", func() error { aiTrafficDetail = aiTrafficDrilldown(ctx, h, hours*60); return ctx.Err() })
	// 30-day trend chart 1: aggregate all nginx requests from unmask_cookie_minute
	// into a stacked bar with 3 categories: white / PoW / not pass (only
	// available when the nginx access_log includes the rendered conf).
	run("DailyPassByDay", func() error {
		dctx, dcancel := queryCtx(15 * time.Second)
		defer dcancel()
		var derr error
		dailyKind, dailyTotal, derr = dashboard.DailyPassByDay(dctx, h.DB, site, hosts, 30, loc)
		return derr
	})
	// 30-day trend chart 2 (legacy): phase='serve' stacked-bar by classify.IsBot.
	// High cardinality (tens of thousands of distinct UA x verdict x IP).
	// Separate ctx with a longer deadline.
	run("DailyServeByKind", func() error {
		dskCtx, dskCancel := queryCtx(15 * time.Second)
		defer dskCancel()
		var derr error
		dailyServeKind, dailyServeTotal, derr = dashboard.DailyServeByKind(dskCtx, h.DB, site, hosts, 30, botVerdicts, loc)
		return derr
	})
	run("CountriesByServe", func() error {
		var e error
		countries, e = dashboard.CountriesByServe(ctx, h.DB, h.IPGeo, site, hosts, 30, 15)
		return e
	})
	// 30-day country breakdown of ALL requests (= same source as DailyPassByDay,
	// rolled up with a country dimension).  Empty when nginxlog or ipgeo is off.
	run("DailyPassByCountry", func() error {
		dcctx, dccancel := queryCtx(15 * time.Second)
		defer dccancel()
		var derr error
		dailyCountry, derr = dashboard.DailyPassByCountry(dcctx, h.DB, site, 30, loc)
		return derr
	})
	// Per-day unique-IP estimate over the same 30-day window (= HLL merge of
	// unmask_traffic_hll(kind='ip')).  Empty when nginxlog is off.
	run("DailyUniqueIPs", func() error {
		dunCtx, dunCancel := queryCtx(15 * time.Second)
		defer dunCancel()
		var derr error
		dailyUniq, derr = dashboard.DailyUniqueIPs(dunCtx, h.DB, site, 30, loc)
		return derr
	})
	// Race wg.Wait against the overall deadline so a slow card (e.g. one of
	// the 30-day raw scans on a big operator DB) doesn't pin the whole
	// handler.  pure-Go sqlite (= glebarez/sqlite/modernc) doesn't respect
	// context cancel, so the underlying scan keeps going as an orphan
	// goroutine until it finishes -- but the handler returns now with the
	// cards that came back in time, same shape as a per-query timeout would
	// have produced.
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-ctx.Done():
		log.Printf("dashboard: overall deadline reached, rendering partial (site=%s hosts=%v range=%s)", site, hosts, rng)
	}
	// Cards that errored (or panicked) -- surfaced as a "data incomplete" banner
	// so an operator doesn't read a silently-empty card as a real zero.  Copied
	// under the lock since a timed-out card's goroutine may still be appending.
	cardMu.Lock()
	failedCardList := append([]string(nil), failedCards...)
	cardMu.Unlock()
	if qElapsed := time.Since(qStart); qElapsed > 800*time.Millisecond {
		log.Printf("stats queries: %v elapsed (site=%s hosts=%v range=%s aggReady=%v)",
			qElapsed, site, hosts, rng, dashboard.HourlyAggReady())
	}

	// LastSeen / Date cells on every row carry the SQL driver's UTC datetime
	// text by default.  Reformat them in the operator's TZ before render --
	// the data-ts attribute is the source of truth, the string is just the
	// readable cell.  Cheap (= a few hundred rows total) and only touches
	// fields the helper recognises (= LastSeen/LastSeenTS, Date/DateTS).
	dashboard.ApplyDisplayLoc(cookieRows, loc)
	dashboard.ApplyDisplayLoc(rlIPs, loc)
	dashboard.ApplyDisplayLoc(rlPaths, loc)
	dashboard.ApplyDisplayLoc(flagsRows, loc)
	dashboard.ApplyDisplayLoc(verdictDist, loc)
	dashboard.ApplyDisplayLoc(hitRows, loc)
	dashboard.ApplyDisplayLoc(loopRows, loc)
	dashboard.ApplyDisplayLoc(verifyNG, loc)
	dashboard.ApplyDisplayLoc(cookieFails, loc)
	dashboard.ApplyDisplayLoc(stealth, loc)
	dashboard.ApplyDisplayLoc(jsErrs, loc)
	dashboard.ApplyDisplayLoc(jsForeign, loc)
	dashboard.ApplyDisplayLoc(dailyKind, loc)
	dashboard.ApplyDisplayLoc(dailyTotal, loc)
	dashboard.ApplyDisplayLoc(dailyServeKind, loc)
	dashboard.ApplyDisplayLoc(dailyServeTotal, loc)
	dashboard.ApplyDisplayLoc(countries, loc)
	dashboard.ApplyDisplayLoc(dailyCountry, loc)
	dashboard.ApplyDisplayLoc(dailyUniq, loc)

	// funnel is the centerpiece, so a confirmed error returns 500.  Other
	// cards may be missing; render continues with "0 entries" (same
	// degradation policy as the old sequential version).  Note we only fail
	// the page on a true error -- if the overall deadline fired before
	// funnel returned, funnel / funnelErr are both nil and we render the
	// dashboard with an empty funnel card.
	if funnelErr != nil {
		log.Printf("funnel: %v", funnelErr)
		http.Error(w, "db error: "+funnelErr.Error(), http.StatusInternalServerError)
		return
	}
	rlPathQueriesJSON, _ := json.Marshal(rlPathQueries)
	countriesJSON, _ := json.Marshal(countries)

	// All IP-display cards use a unified "flag + IP + popover" layout (same as
	// bans / hunt).  Attach the IP-geo-looked-up country code to each row.
	// Duplicate lookups for the same IP are avoided via cache.  If IP-geo is not
	// loaded, leave it empty (template falls back to the "??" flag).
	ccCache := map[string]string{}
	lookupCC := func(ip string) string {
		if ip == "" || h.IPGeo == nil || !h.IPGeo.Loaded() {
			return ""
		}
		if cc, ok := ccCache[ip]; ok {
			return cc
		}
		cc := h.IPGeo.LookupInfo(ip).Country
		ccCache[ip] = cc
		return cc
	}
	for i := range rlIPs {
		rlIPs[i].CountryCode = lookupCC(rlIPs[i].IP)
	}
	for i := range loopRows {
		loopRows[i].CountryCode = lookupCC(loopRows[i].IP)
	}
	for i := range verifyNG {
		verifyNG[i].CountryCode = lookupCC(verifyNG[i].IP)
	}
	for i := range cookieFails {
		cookieFails[i].CountryCode = lookupCC(cookieFails[i].IP)
	}
	for i := range stealth {
		stealth[i].CountryCode = lookupCC(stealth[i].IP)
	}
	for i := range jsErrs {
		jsErrs[i].CountryCode = lookupCC(jsErrs[i].IP)
	}
	for i := range jsForeign {
		jsForeign[i].CountryCode = lookupCC(jsForeign[i].IP)
	}

	// CAPTCHA pass report: classify each pass's JA4 verdict as bot vs ok via the
	// same verdict->action map the funnel uses (bot / suspect => "bot"), roll the
	// per-verdict counts into the KPI, and tag the detail rows for highlighting.
	isBotVerdict := func(v string) bool {
		a := verdictAction[v]
		return a == "bot" || a == "suspect"
	}
	var cpTotal, cpBot int
	for v, n := range cpVerdictCounts {
		cpTotal += n
		if isBotVerdict(v) {
			cpBot += n
		}
	}
	for i := range cpTopIPs {
		cpTopIPs[i].IsBot = isBotVerdict(cpTopIPs[i].Verdict)
		cpTopIPs[i].CountryCode = lookupCC(cpTopIPs[i].IP)
	}
	for i := range cpRecent {
		cpRecent[i].IsBot = isBotVerdict(cpRecent[i].Verdict)
		cpRecent[i].CountryCode = lookupCC(cpRecent[i].IP)
	}
	// Which axis raised each solved CAPTCHA (force_reason breakdown), most-passed
	// first -- a bot-facing axis (header / asn / geo / honeypot / banned) topping
	// the list is where CAPTCHA-solving is concentrated.
	type cpReasonRow struct {
		Reason string
		Count  int
	}
	cpByReason := make([]cpReasonRow, 0, len(cpForceReasonCounts))
	for r, n := range cpForceReasonCounts {
		cpByReason = append(cpByReason, cpReasonRow{Reason: r, Count: n})
	}
	sort.Slice(cpByReason, func(i, j int) bool {
		if cpByReason[i].Count != cpByReason[j].Count {
			return cpByReason[i].Count > cpByReason[j].Count
		}
		return cpByReason[i].Reason < cpByReason[j].Reason
	})
	// Fail-side twin (verify_ng by axis), same shape + ordering.
	cpFailByReason := make([]cpReasonRow, 0, len(cpFailForceReasonCounts))
	for r, n := range cpFailForceReasonCounts {
		cpFailByReason = append(cpFailByReason, cpReasonRow{Reason: r, Count: n})
	}
	sort.Slice(cpFailByReason, func(i, j int) bool {
		if cpFailByReason[i].Count != cpFailByReason[j].Count {
			return cpFailByReason[i].Count > cpFailByReason[j].Count
		}
		return cpFailByReason[i].Reason < cpFailByReason[j].Reason
	})
	captchaReport := struct {
		Total, Bot, Ok int
		TopIPs         []dashboard.CaptchaPassIPRow
		Recent         []dashboard.CaptchaPassRow
		ByReason       []cpReasonRow
	}{Total: cpTotal, Bot: cpBot, Ok: cpTotal - cpBot, TopIPs: cpTopIPs, Recent: cpRecent, ByReason: cpByReason}

	// Cookie reuse rankings: the reuse table holds the JA4 STRING (not a verdict
	// name), so classify each JA4 -> verdict action via matchJA4 (the same
	// resolver the forward-auth path uses), tagging bot/suspect rows for
	// highlight.  Both kinds get the identical treatment.
	reuseNginxCfg := h.cfg().Nginx
	for _, rows := range [][]dashboard.CookieReuseRow{cpReuse, powReuse, rebindReuse} {
		for i := range rows {
			verdict, action := matchJA4(rows[i].JA4, reuseNginxCfg)
			rows[i].Verdict = verdict
			rows[i].IsBot = action == "bot" || action == "suspect"
			rows[i].CountryCode = lookupCC(rows[i].IP)
		}
	}

	type kindPt struct {
		Date string `json:"date"`
		Kind int    `json:"kind"`
		Req  int    `json:"req"`
	}
	kindPts := make([]kindPt, 0, len(dailyKind))
	var sumWhite, sumCaptcha, sumPow, sumNot int
	for _, b := range dailyKind {
		kindPts = append(kindPts, kindPt{b.Date, b.Kind, b.Req})
		switch b.Kind {
		case dashboard.KindWhitePass:
			sumWhite += b.Req
		case dashboard.KindCaptchaPass:
			sumCaptcha += b.Req
		case dashboard.KindPoWPass:
			sumPow += b.Req
		case dashboard.KindNotPass:
			sumNot += b.Req
		}
	}
	sumTotal := sumWhite + sumCaptcha + sumPow + sumNot
	dailyKindJSON, _ := json.Marshal(kindPts)
	servePts := make([]kindPt, 0, len(dailyServeKind))
	for _, b := range dailyServeKind {
		servePts = append(servePts, kindPt{b.Date, b.Kind, b.Req})
	}
	dailyServeKindJSON, _ := json.Marshal(servePts)

	// Per-day unique-IP merge into the existing DailyTotal slice so the
	// table renders day + req + uniq alongside one another.  Keys match
	// because both queries use server-local DATE() bucketing.
	uniqByDate := make(map[string]int64, len(dailyUniq))
	for _, u := range dailyUniq {
		uniqByDate[u.Date] = u.UniqIPs
	}
	for i := range dailyTotal {
		if v, ok := uniqByDate[dailyTotal[i].Date]; ok {
			dailyTotal[i].UniqIPs = int(v)
		}
	}

	// Country ranking for ALL requests over the last 30 days.  Built by
	// summing dailyCountry's per-day kind=total rows; mirrors the shape
	// of dashboard.CountryRow so the same horizontal-bar partial renders
	// it.  When ipgeo / nginxlog is off, dailyCountry is empty and this
	// list is empty too -- the template hides the card in that case.
	countryAllReq := make(map[string]int)
	for _, b := range dailyCountry {
		countryAllReq[b.Country] += b.Req
	}
	type countryAllRow struct {
		CountryCode string `json:"CountryCode"`
		Req         int    `json:"Req"`
	}
	countriesAll := make([]countryAllRow, 0, len(countryAllReq))
	for cc, n := range countryAllReq {
		countriesAll = append(countriesAll, countryAllRow{CountryCode: cc, Req: n})
	}
	sort.Slice(countriesAll, func(i, j int) bool { return countriesAll[i].Req > countriesAll[j].Req })
	if len(countriesAll) > 15 {
		countriesAll = countriesAll[:15]
	}
	countriesAllJSON, _ := json.Marshal(countriesAll)

	now := time.Now()
	rangeStart := now.Add(-time.Duration(hours) * time.Hour)
	rangeEnd := now
	if (rng == "custom" || rng == "all") && customValid {
		rangeStart = time.Unix(win.Start, 0)
		rangeEnd = time.Unix(win.End, 0)
	}
	// Custom-range calendar: pre-fill the date inputs with the current window's
	// dates (operator TZ) and bound them to [oldest event, today] so the operator
	// can only pick a period that actually has data behind it.
	dataMinDate := ""
	if oldestTS > 0 {
		dataMinDate = time.Unix(oldestTS, 0).In(loc).Format("2006-01-02")
	}
	dataMaxDate := now.In(loc).Format("2006-01-02")
	customFrom := strings.TrimSpace(r.URL.Query().Get("from"))
	if customFrom == "" {
		customFrom = rangeStart.In(loc).Format("2006-01-02")
	}
	customTo := strings.TrimSpace(r.URL.Query().Get("to"))
	if customTo == "" {
		customTo = rangeEnd.In(loc).Format("2006-01-02")
	}

	data := map[string]any{
		"Lang":  i18n.Resolve(r),
		"TZ":    resolveTZ(r),
		"Site":  site,
		"Range": rng,
		// RangeStartTS = epoch sec UTC.  JS reformats in the browser TZ.
		"RangeStartTS":       rangeStart.Unix(),
		"RangeStartFallback": rangeStart.In(resolveLocation(r)).Format("2006-01-02 15:04 MST"),
		"RangeEndTS":         rangeEnd.Unix(),
		"RangePresets":       rangePresets,
		"CustomFrom":         customFrom,
		"CustomTo":           customTo,
		"DataMinDate":        dataMinDate,
		"DataMaxDate":        dataMaxDate,
		"FailedCards":        failedCardList,
		"Funnel":             funnel,
		"CookieRows":         cookieRows,
		"RLSummary":          rlSummary,
		"RLIPs":              rlIPs,
		"RLPaths":            rlPaths,
		"RLPathQueriesJSON":  template.JS(rlPathQueriesJSON),
		"FlagsRows":          flagsRows,
		"VerdictDist":        verdictDist,
		"HitRows":            hitRows,
		"LoopRows":           loopRows,
		"VerifyNG":           verifyNG,
		"VerifyNGByReason":   cpFailByReason,
		"CookieFails":        cookieFails,
		"Stealth":            stealth,
		"JSErrors":           jsErrs,
		"JSForeignErrors":    jsForeign,
		"JSForeignCount":     jsForeignCount,
		"CaptchaReport":      captchaReport,
		"CaptchaReuse":       cpReuse,
		"PowReuse":           powReuse,
		"RebindReuse":        rebindReuse,
		"RebindLineages":     rebindLineageRows(ctx, h, rebindLineages),
		"AITrafficServed":    aiTraffic,
		"AITraffic":          aiTrafficAll,
		"AITrafficDetail":    aiTrafficDetail,
		"DailyKindJSON":      template.JS(dailyKindJSON),
		"DailyTotal":         dailyTotal,
		"PassSumTotal":       sumTotal,
		"PassSumWhite":       sumWhite,
		"PassSumCaptcha":     sumCaptcha,
		"PassSumPoW":         sumPow,
		"PassSumNot":         sumNot,
		"DailyServeKindJSON": template.JS(dailyServeKindJSON),
		"DailyServeTotal":    dailyServeTotal,
		"Countries":          countries,
		"CountriesJSON":      template.JS(countriesJSON),
		"CountriesAll":       countriesAll,
		"CountriesAllJSON":   template.JS(countriesAllJSON),
		"IPGeoLoaded":        h.IPGeo != nil && h.IPGeo.Loaded(),
		// The persistent BAN list section was removed from the dashboard (the
		// /admin/bans/ tab retains all that functionality).
		// Reverse map: verdict name -> action ("bot"/"suspect"/"ok").  Used by funnel etc. for badge judgment.
		"VerdictAction": verdictAction,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		log.Printf("dashboard render: %v", err)
	}
}

// AdminEventsStream: GET {base}/admin/api/events/stream?site=&phase=&since=
//
// Stream newly-arrived rows from unmask_event via Server-Sent Events.
//   - since omitted: anchor at MAX(id) at start time (events "from now on" only).
//   - Poll every 1 second; emit progress as `data: <json>\n\n`.
//   - Connection ending (browser close / disconnect) terminates the goroutine immediately.
func (h *Handler) AdminEventsStream(w http.ResponseWriter, r *http.Request) {
	// site filter (= shared site_picker, single-select.  cookie / ?site=).
	// No charset check needed: FetchSince binds it as a ? parameter.
	site := resolveSiteFilter(r)
	phase := r.URL.Query().Get("phase")
	if phase != "" && !events.IsValidPhase(phase) {
		http.Error(w, "invalid phase", http.StatusBadRequest)
		return
	}
	// host filter (global scope of the shared host_picker; sourced from unmask_hosts cookie / ?host=).
	hosts := resolveHostFilter(r)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// Disable the http.Server WriteTimeout for SSE.  Without this it would drop at 15s.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // prevent nginx proxy buffering (separate-layer safety net)
	// Determine the anchor id: query > 0 / 'now' = current MAX.
	var sinceID int64
	if v := r.URL.Query().Get("since"); v != "" && v != "now" {
		fmt.Sscanf(v, "%d", &sinceID)
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		mx, err := events.MaxID(ctx, h.DB)
		cancel()
		if err == nil {
			sinceID = mx
		}
	}

	// Keep-alive comment ping (heartbeat).  Sent at 5 s for two reasons:
	//   1. Intermediaries (= corporate proxies / GCP HTTPS LB) cut idle SSE
	//      sessions; 5 s is well below the typical 30–60 s idle window.
	//   2. nginx HTTP/2 (= front-of-Go in many installs) can stall a
	//      proxy_buffering=off stream until the first wire write occurs;
	//      pinging frequently keeps the wire moving.
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()
	// Poll interval: tradeoff between client load and "liveness".  At 2 seconds
	// the client's JSON.parse + DOM update halves and feels noticeably lighter
	// (1->2s isn't perceptibly more lag).  Going much higher loses the tail
	// effect, so 2 seconds.
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()

	// initial retry hint + 2 KiB comment padding.  Some HTTP/2 proxies
	// (= nginx with proxy_buffering off + gzip default + chunked upstream)
	// hold back the response until ~2 KiB has been buffered, leaving the
	// browser in CONNECTING for tens of seconds before the first event.
	// SSE allows comment lines (lines starting with ":") so a one-shot
	// padded comment is a no-op to clients and forces the proxy to flush.
	_, _ = w.Write([]byte("retry: 5000\n\n"))
	_, _ = w.Write([]byte(":" + strings.Repeat(" ", 2048) + "\n\n"))
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case <-poll.C:
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			rows, err := events.FetchSince(ctx, h.DB, sinceID, site, phase, hosts, 100)
			cancel()
			if err != nil {
				_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n",
					strings.ReplaceAll(err.Error(), "\n", " "))
				flusher.Flush()
				continue
			}
			for _, row := range rows {
				buf, _ := json.Marshal(row)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", buf)
				if row.ID > sinceID {
					sinceID = row.ID
				}
			}
			if len(rows) > 0 {
				flusher.Flush()
			}
		}
	}
}

// AdminFunnelJSON: GET {base}/admin/api/funnel?site=&range=24h
func (h *Handler) AdminFunnelJSON(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng != "7d" && rng != "30d" {
		rng = "24h"
	}
	// site filter (= shared site_picker, single-select.  cookie / ?site=).
	// siteCond validates the value before use; "" / "default" = all sites.
	site := resolveSiteFilter(r)
	hosts := h.dashboardHosts(r)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	rows, err := dashboard.Funnel(ctx, h.DB, site, hosts, dashboard.RangeHours(rng), dashboard.BotVerdictNames(h.cfg().Nginx), h.VerdictRegistry(), site != "" && h.cfg().Sites.DefinedSet()[site])
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1, "site": site, "range": rng, "funnel": rows})
}
