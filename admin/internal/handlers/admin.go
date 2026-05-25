// dashboard / admin endpoints.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
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
func resolveTZ(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(tzCookieName)
	if err != nil || c == nil {
		return ""
	}
	v := c.Value
	if v == "browser" || v == "auto" {
		return ""
	}
	// safety: cookie value is expected to be an IANA tz name (e.g. "Asia/Tokyo").  Accept only alnum + / + _ + -.
	for _, ch := range v {
		if !(ch >= 'A' && ch <= 'Z') && !(ch >= 'a' && ch <= 'z') &&
			!(ch >= '0' && ch <= '9') && ch != '/' && ch != '_' && ch != '-' && ch != '+' {
			return ""
		}
	}
	return v
}

var (
	dashboardTmpl     *template.Template
	dashboardTmplOnce sync.Once
	dashboardTmplErr  error
)

func loadDashboardTemplate() (*template.Template, error) {
	dashboardTmplOnce.Do(func() {
		funcs := template.FuncMap{
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
			// firstN returns the first n elements of slice s (= caps a table to
			// a few rows without trimming the underlying data). Non-slice / n<0
			// returns s unchanged; n past the end is clamped.
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
		// During the install wizard, redirect every admin path to /admin/setup/.
		if needed, _ := h.SetupNeeded(r); needed {
			http.Redirect(w, r, h.Settings.Server.BasePath+"/admin/setup/", http.StatusFound)
			return
		}
		// Check the remote IP against the admin_allow_from list (enforced at the
		// handler layer so deployments that don't include the rendered nginx conf
		// still get the restriction).
		ip := clientIP(r)
		if !ipAllowed(ip, h.Settings.Nginx.AdminAllowFrom) {
			log.Printf("admin IP denied: ip=%s path=%s allow_from=%v", ip, r.URL.Path, h.Settings.Nginx.AdminAllowFrom)
			http.Error(w, "forbidden: your IP is not in admin_allow_from", http.StatusForbidden)
			return
		}
		secret := h.Settings.Secret.BVSecret
		if c, err := r.Cookie(sessionCookieName); err == nil {
			if pay := verifySessionCookie(secret, c.Value); pay != nil {
				// Sliding extension on each request: refresh when remaining lifetime drops below half of TTL.
				if sessionNeedsRefresh(pay) {
					secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
					http.SetCookie(w, issueSessionCookie(secret, pay.UserID, pay.Role, secure, pay.Remember))
				}
				ctx := context.WithValue(r.Context(), sessionCtxKey{}, pay)
				next(w, r.WithContext(ctx))
				return
			}
		}
		// failure
		if strings.HasPrefix(r.URL.Path, h.Settings.Server.BasePath+"/admin/api/") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": 0, "error": "unauthorized"})
			return
		}
		ret := r.URL.Path
		if r.URL.RawQuery != "" {
			ret += "?" + r.URL.RawQuery
		}
		dst := h.Settings.Server.BasePath + "/admin/login?return=" + url.QueryEscape(ret)
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
	return rank[role] >= rank[min]
}

// flashCookiePrefix is the prefix for flash cookies ("unmask_flash_<key>").
// Avoids putting long messages in the query string; passed via a short-lived
// cookie and consumed on the next GET.
const flashCookiePrefix = "unmask_flash_"

// setFlash writes a flash message to a cookie just before a redirect.  Expires
// after 60 seconds (safety net for cases where the next GET never happens;
// normally readFlash deletes it on the next GET).
func setFlash(w http.ResponseWriter, basePath, key, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookiePrefix + key,
		Value:    url.QueryEscape(msg),
		Path:     basePath + "/admin/",
		MaxAge:   60,
		HttpOnly: false,
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
		SameSite: http.SameSiteLaxMode,
	})
	v, err := url.QueryUnescape(c.Value)
	if err != nil {
		return ""
	}
	return v
}

// AdminIPAllowMiddleware enforces remote-IP access control on /admin/*.
//
// Configuration:
//   - settings.Nginx.AdminAllowFrom is the source of truth (editable via web UI).
//   - An empty list means **allow all** (legacy behavior; avoids accidentally
//     disabling access on existing installs).  Almost every install has the
//     wizard set this to a non-empty list.
//   - Each entry is an IP exact match or CIDR (e.g. "192.168.0.0/24").
//
// The rendered nginx server.conf emits the equivalent allow / deny, but
// existing integrated deployments that don't include the rendered conf
// won't see it.  Enforcing this at the handler layer guarantees a consistent
// restriction independent of nginx config.
//
// Not applied during the install wizard (/admin/setup/) so the initial install
// can't lock you out before any IP is configured.  Applied to /admin/login to
// prevent brute force from unauthorized IPs.
func (h *Handler) AdminIPAllowMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Bypass during the install wizard (setup token guards it separately).
		if needed, _ := h.SetupNeeded(r); needed {
			next(w, r)
			return
		}
		ip := clientIP(r)
		if !ipAllowed(ip, h.Settings.Nginx.AdminAllowFrom) {
			log.Printf("admin IP denied: ip=%s path=%s allow_from=%v", ip, r.URL.Path, h.Settings.Nginx.AdminAllowFrom)
			http.Error(w, "forbidden: your IP is not in admin_allow_from", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// ipAllowed reports whether ip matches any entry in allowList.  Supports both
// exact and CIDR.  Empty allowList means allow all (legacy compat; avoids
// lockout from misconfiguration).
func ipAllowed(ip string, allowList []string) bool {
	if len(allowList) == 0 {
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
// "Me" / "MeName" / "BasePath" (consumed by the user_menu partial) plus the
// host / site picker data consumed by the header_tools partial.  When
// unauthenticated (e.g. login page) Me / MeName are skipped; BasePath and the
// picker data are always set (the pickers are not session-dependent).
func (h *Handler) addMeToData(r *http.Request, data map[string]any) {
	if _, ok := data["BasePath"]; !ok {
		data["BasePath"] = h.Settings.Server.BasePath
	}
	if pay := SessionFromContext(r); pay != nil {
		data["Me"] = pay
		if h.UserRepo != nil {
			if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
				data["MeName"] = u.Username
			}
		}
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
		if dis := h.Settings.Hosts.Disabled; len(dis) > 0 {
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
		definedMode := h.Settings.Sites.ResolvedMode() == settings.SiteModeDefined
		var opts []string
		if definedMode {
			opts = append(opts, h.Settings.Sites.Defined...)
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
		"BasePath":    h.Settings.Server.BasePath,
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
	base := h.Settings.Server.BasePath
	ret := r.FormValue("return")
	if ret == "" || !strings.HasPrefix(ret, "/") {
		ret = base + "/admin/"
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	rejectInvalid := func() {
		// audit best-effort
		if h.UserRepo != nil {
			h.UserRepo.Record(r.Context(), 0, username, "login_failed", "", "")
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
		rejectInvalid()
		return
	}
	if err := user.CheckPassword(u.PasswordHash, password); err != nil {
		rejectInvalid()
		return
	}
	// success
	h.UserRepo.TouchLastLogin(r.Context(), u.ID)
	h.UserRepo.Record(r.Context(), u.ID, u.Username, "login", "", "")
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	remember := r.FormValue("remember") != ""
	http.SetCookie(w, issueSessionCookie(h.Settings.Secret.BVSecret, u.ID, u.Role, secure, remember))
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
	http.Redirect(w, r, h.Settings.Server.BasePath+"/admin/login", http.StatusFound)
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
	if err != nil {
		log.Printf("sites: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	// site <= 1 -> internally dispatch and render the dashboard directly.  list=1 forces the list.
	if r.URL.Query().Get("list") != "1" {
		target := defaultSite
		if len(sites) == 1 {
			target = sites[0].Site
		}
		h.renderDashboard(w, r, target)
		return
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	rangeStart := now.Add(-time.Duration(hours) * time.Hour)
	data := map[string]any{
		"Lang":  i18n.Resolve(r),
		"TZ":    resolveTZ(r),
		"Range": rng,
		// RangeStartTS = epoch sec UTC.  Emit in the template as <time class="js-datetime"
		// data-ts="...">; JS reformats in the browser TZ.
		"RangeStartTS":       rangeStart.Unix(),
		"RangeStartFallback": rangeStart.UTC().Format("2006-01-02 15:04 UTC"),
		"Driver":             string(h.DB.Driver),
		"Sites":              sites,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "site_list.html", data); err != nil {
		log.Printf("site list render: %v", err)
	}
}

// AdminDashboard: GET {base}/admin/{site}/  — per-site dashboard.
func (h *Handler) AdminDashboard(w http.ResponseWriter, r *http.Request) {
	site, ok := pickSite(r)
	if !ok {
		http.Error(w, "invalid site id", http.StatusBadRequest)
		return
	}
	h.renderDashboard(w, r, site)
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
	for _, d := range h.Settings.Hosts.Disabled {
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

// renderDashboard renders the dashboard template for the result of pickSite.
// Called by both AdminDashboard (/admin/{site}/) and AdminSiteList (/admin/
// when site<=1).
func (h *Handler) renderDashboard(w http.ResponseWriter, r *http.Request, site string) {
	// The dashboard scopes by the shared site_picker (single-select), not by
	// the legacy /admin/{site}/ path segment.  cookie / ?site=; "" = all sites.
	site = resolveSiteFilter(r)
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		log.Printf("dashboard tmpl load: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	rng := r.URL.Query().Get("range")
	if rng != "7d" && rng != "30d" {
		rng = "24h"
	}
	hours := dashboard.RangeHours(rng)

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

	// Helper to compose a per-query timeout.  Assigns heavy queries (e.g. the
	// 30-day aggregate) their own ctx so an upstream slow query doesn't cascade.
	queryCtx := func(d time.Duration) (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, d)
	}

	// Collect verdict names judged "action=bot or suspect" by the settings.
	// Used by the SQL stealth count + classify bot judgment.
	botVerdicts := dashboard.BotVerdictNames(h.Settings.Nginx)

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
	for _, p := range h.Settings.Nginx.JA4Verdicts.Extra {
		verdictAction[p.Verdict] = p.Action
	}

	// Each dashboard card is an independent read query.  Previously executed
	// sequentially, so the whole page latency was queries x per-query latency,
	// degrading linearly as the event table grew.  Run them in parallel using
	// WAL + conn pool.  A semaphore caps concurrency at 6, leaving conn pool
	// headroom (max 8) for challenge writes.
	var (
		funnel          []dashboard.FunnelRow
		funnelErr       error
		cookieRows      []dashboard.CookieStatusRow
		rlSummary       dashboard.RLSummary
		rlIPs           []dashboard.RLIPRow
		rlPaths         []dashboard.RLPathRow
		rlPathQueries   map[string][]dashboard.RLQueryCount
		flagsRows       []dashboard.FlagsRow
		verdictDist     []dashboard.VerdictCount
		hitRows         []dashboard.CaptchaForceRow
		loopRows        []dashboard.ReloadLoopRow
		verifyNG        []dashboard.VerifyNGRow
		cookieFails     []dashboard.CookieFailRow
		stealth         []dashboard.StealthRow
		jsErrs          []dashboard.JSErrorRow
		dailyKind       []dashboard.DailyKindBucket
		dailyTotal      []dashboard.DailyTotal
		dailyServeKind  []dashboard.DailyKindBucket
		dailyServeTotal []dashboard.DailyTotal
		countries       []dashboard.CountryRow
		dailyCountry    []dashboard.DailyCountryBucket
		dailyUniq       []dashboard.DailyUniq
	)
	qStart := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn()
		}()
	}
	run(func() {
		fctx, fcancel := queryCtx(5 * time.Second)
		defer fcancel()
		funnel, funnelErr = dashboard.Funnel(fctx, h.DB, site, hosts, hours, botVerdicts, h.VerdictRegistry())
	})
	run(func() { cookieRows, _ = dashboard.CookieStatus(ctx, h.DB, site, hosts, hours) })
	run(func() { rlSummary, _ = dashboard.RateLimitSummary(ctx, h.DB, site, hosts, hours) })
	run(func() { rlIPs, _ = dashboard.RateLimitIPs(ctx, h.DB, site, hosts, hours, 30) })
	run(func() { rlPaths, _ = dashboard.RateLimitPaths(ctx, h.DB, site, hosts, hours, 30) })
	run(func() { rlPathQueries, _ = dashboard.RateLimitQueriesByPath(ctx, h.DB, site, hosts, hours, 5) })
	run(func() { flagsRows, _ = dashboard.FlagsDistribution(ctx, h.DB, site, hosts, hours) })
	run(func() { verdictDist, _ = dashboard.VerdictDistribution(ctx, h.DB, site, hosts, hours) })
	run(func() { hitRows, _ = dashboard.CaptchaForceBreakdown(ctx, h.DB, site, hosts, hours) })
	run(func() { loopRows, _ = dashboard.ReloadLoops(ctx, h.DB, site, hosts, hours) })
	run(func() { verifyNG, _ = dashboard.VerifyNGRanking(ctx, h.DB, site, hosts, hours, 30) })
	run(func() { cookieFails, _ = dashboard.CookieSetFails(ctx, h.DB, site, hosts, hours) })
	run(func() { stealth, _ = dashboard.StealthPassed(ctx, h.DB, site, hosts, hours, botVerdicts) })
	run(func() { jsErrs, _ = dashboard.JSErrors(ctx, h.DB, site, hosts, hours) })
	// 30-day trend chart 1: aggregate all nginx requests from unmask_cookie_minute
	// into a stacked bar with 3 categories: white / PoW / not pass (only
	// available when the nginx access_log includes the rendered conf).
	run(func() {
		dctx, dcancel := queryCtx(15 * time.Second)
		defer dcancel()
		var derr error
		dailyKind, dailyTotal, derr = dashboard.DailyPassByDay(dctx, h.DB, site, hosts, 30)
		if derr != nil {
			log.Printf("daily pass by day: %v", derr)
		}
	})
	// 30-day trend chart 2 (legacy): phase='serve' stacked-bar by classify.IsBot.
	// High cardinality (tens of thousands of distinct UA x verdict x IP).
	// Separate ctx with a longer deadline.
	run(func() {
		dskCtx, dskCancel := queryCtx(15 * time.Second)
		defer dskCancel()
		var derr error
		dailyServeKind, dailyServeTotal, derr = dashboard.DailyServeByKind(dskCtx, h.DB, site, hosts, 30, botVerdicts)
		if derr != nil {
			log.Printf("daily serve by kind: %v", derr)
		}
	})
	run(func() { countries, _ = dashboard.CountriesByServe(ctx, h.DB, h.IPGeo, site, hosts, 30, 15) })
	// 30-day country breakdown of ALL requests (= same source as DailyPassByDay,
	// rolled up with a country dimension).  Empty when nginxlog or ipgeo is off.
	run(func() {
		dcctx, dccancel := queryCtx(15 * time.Second)
		defer dccancel()
		var derr error
		dailyCountry, derr = dashboard.DailyPassByCountry(dcctx, h.DB, site, 30)
		if derr != nil {
			log.Printf("daily pass by country: %v", derr)
		}
	})
	// Per-day unique-IP estimate over the same 30-day window (= HLL merge of
	// unmask_traffic_hll(kind='ip')).  Empty when nginxlog is off.
	run(func() {
		dunCtx, dunCancel := queryCtx(15 * time.Second)
		defer dunCancel()
		var derr error
		dailyUniq, derr = dashboard.DailyUniqueIPs(dunCtx, h.DB, site, 30)
		if derr != nil {
			log.Printf("daily unique ips: %v", derr)
		}
	})
	wg.Wait()
	if qElapsed := time.Since(qStart); qElapsed > 800*time.Millisecond {
		log.Printf("dashboard queries: %v elapsed (site=%s hosts=%v range=%s aggReady=%v)",
			qElapsed, site, hosts, rng, dashboard.HourlyAggReady())
	}

	// funnel is the centerpiece, so error returns 500.  Other cards may be
	// missing; render continues with "0 entries" (same degradation policy as
	// the old sequential version).
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

	data := map[string]any{
		"Lang":  i18n.Resolve(r),
		"TZ":    resolveTZ(r),
		"Site":  site,
		"Range": rng,
		// RangeStartTS = epoch sec UTC.  JS reformats in the browser TZ.
		"RangeStartTS":       rangeStart.Unix(),
		"RangeStartFallback": rangeStart.UTC().Format("2006-01-02 15:04 UTC"),
		"Driver":             string(h.DB.Driver),
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
		"CookieFails":        cookieFails,
		"Stealth":            stealth,
		"JSErrors":           jsErrs,
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
	rows, err := dashboard.Funnel(ctx, h.DB, site, hosts, dashboard.RangeHours(rng), dashboard.BotVerdictNames(h.Settings.Nginx), h.VerdictRegistry())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1, "site": site, "range": rng, "funnel": rows})
}
