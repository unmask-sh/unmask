// /admin/ — top dashboard (= summary page).
//
// Layout:
//   - 4 KPI boxes: events / serves / verify_ok / currently-BANNED, all over the last 24h
//   - 5 most recent detections (= latest unmask_event rows)
//   - shortcuts to each tab (= stats / bot hunt / persistent BAN / settings / docs)
//
// Data source is only the existing events package.  Lightweight.
package handlers

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// decodeCookieValue percent-decodes a cookie value.  The pickers write cookies
// with the browser's encodeURIComponent (so a comma-joined host list becomes
// "a%2Cb", an IPv6 site keeps its %3A), but net/http hands back the raw value
// undecoded — without this the host filter would split "a%2Cb" into one junk
// entry.  Falls back to the raw value on a malformed escape.
func decodeCookieValue(v string) string {
	if d, err := url.PathUnescape(v); err == nil {
		return d
	}
	return v
}

// AdminTopOverview: GET /admin/  — top dashboard.
func (h *Handler) AdminTopOverview(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// host filter (= global scope of the shared host_picker.  Sourced from cookie / ?host=).
	hosts := resolveHostFilter(r)
	// site filter (= shared site_picker, single-select.  cookie / ?site=).
	site := resolveSiteFilter(r)

	// Last-24h KPIs.  On failure, fall through with 0.
	kpiEvents := countEvents(ctx, h, 1440, "", site, hosts)
	kpiServes := countEvents(ctx, h, 1440, "serve", site, hosts)
	kpiVerify := countEvents(ctx, h, 1440, "verify", site, hosts)

	// BAN has no host axis (= keyed on the IP+JA4 pair, global).  Same number for every host.
	currentBans := 0
	if h.BanMgr != nil {
		currentBans = len(h.BanMgr.Snapshot())
	}

	// 5 most recent detections (= any phase / id desc).
	recentRaw, err := events.FetchPaged(ctx, h.DB, "", "", "", site, hosts, 0, 5, 0)
	if err != nil {
		log.Printf("overview recent: %v", err)
	}
	// IP rendering is unified as "flag + IP + popover" (= same as bans / hunt / dashboard).
	// Tag each row with the IP-geo-looked-up country code.  Leave empty if IP-geo is not loaded.
	type recentRow struct {
		events.Row
		CountryCode string
	}
	geoOK := h.IPGeo != nil && h.IPGeo.Loaded()
	ccCache := map[string]string{}
	recent := make([]recentRow, 0, len(recentRaw))
	for _, r0 := range recentRaw {
		cc := ""
		if geoOK && r0.IP != "" {
			if v, ok := ccCache[r0.IP]; ok {
				cc = v
			} else {
				cc = h.IPGeo.LookupInfo(r0.IP).Country
				ccCache[r0.IP] = cc
			}
		}
		recent = append(recent, recentRow{Row: r0, CountryCode: cc})
	}

	// AI traffic funnel (= last 24h, top of overview).  Five-bucket
	// consolidation of upstream crawler-user-agents.json tags.  Cheap query
	// (= one COUNT/UA scan over the past day) so we can run it on every
	// overview render.
	aiRows := aiTrafficSummary(ctx, h, 1440, hosts)

	// Hosts / HostSelected / SelfHostID (= for the shared host_picker) are
	// injected by addMeToData, which is shared across every admin page.
	data := map[string]any{
		"Lang":           i18n.Resolve(r),
		"TZ":             resolveTZ(r),
		"KPIEvents":      kpiEvents,
		"KPIServes":      kpiServes,
		"KPIVerify":      kpiVerify,
		"KPICurrentBans": currentBans,
		"Recent":         recent,
		"AITraffic":      aiRows,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "overview.html", data); err != nil {
		log.Printf("overview render: %v", err)
	}
}

// AITrafficRow: per-category aggregation for the overview's AI funnel.
// `Served` counts the challenge-served step, `Passed` counts the terminal
// `bv_*` (= visitor cleared PoW / CAPTCHA).  `Total` is all phases combined.
type AITrafficRow struct {
	Category string // "search" / "training" / "agent" / "scraper" / "collector"
	Total    int
	Served   int
	Passed   int
}

// aiTrafficSummary groups unmask_event rows of the last `minutes` window into
// the 5 AI categories defined by classify.AICategory.  Implementation is a
// single SQL scan that returns (user_agent, phase, count) and the Go side
// aggregates — keeps the dashboard schema-stable (= no new ai_category
// column required).  Best-effort on error.
func aiTrafficSummary(ctx context.Context, h *Handler, minutes int, hosts []string) []AITrafficRow {
	stmt := `SELECT user_agent, phase, COUNT(*) AS c
	         FROM unmask_event
	         WHERE date_created > ` + h.DB.NowMinusMinutes(minutes)
	args := []any{}
	if len(hosts) > 0 {
		placeholders := strings.Repeat("?,", len(hosts))
		placeholders = placeholders[:len(placeholders)-1]
		stmt += " AND host IN (" + placeholders + ")"
		for _, hh := range hosts {
			args = append(args, hh)
		}
	}
	stmt += ` GROUP BY user_agent, phase`
	rows, err := h.DB.QueryContext(ctx, stmt, args...)
	if err != nil {
		log.Printf("aiTrafficSummary: %v", err)
		return nil
	}
	defer rows.Close()
	// Order matters for stable rendering even with zero rows.
	order := []string{"search", "training", "agent", "scraper", "collector"}
	byCat := map[string]*AITrafficRow{}
	for _, k := range order {
		byCat[k] = &AITrafficRow{Category: k}
	}
	for rows.Next() {
		var ua, phase string
		var c int
		if err := rows.Scan(&ua, &phase, &c); err != nil {
			continue
		}
		cat := classify.AICategory(ua)
		if cat == "" {
			continue
		}
		r := byCat[cat]
		if r == nil {
			continue
		}
		r.Total += c
		switch phase {
		case "serve":
			r.Served += c
		case "bv_pow_only", "bv_captcha_only", "bv_pow_then_captcha":
			r.Passed += c
		}
	}
	out := make([]AITrafficRow, 0, len(order))
	for _, k := range order {
		out = append(out, *byCat[k])
	}
	return out
}

// countEvents: count of unmask_event rows in the last `minutes`.  Empty phase
// means all rows.  Non-empty hosts narrows via IN (...) for multi-host filtering.
// Best-effort (= on error, return 0 and just log).
func countEvents(ctx context.Context, h *Handler, minutes int, phase, site string, hosts []string) int {
	stmt := `SELECT COUNT(*) FROM unmask_event WHERE date_created > ` + h.DB.NowMinusMinutes(minutes)
	args := []any{}
	if phase != "" {
		stmt += " AND phase = ?"
		args = append(args, phase)
	}
	if site != "" {
		stmt += " AND site = ?"
		args = append(args, site)
	}
	if len(hosts) > 0 {
		placeholders := strings.Repeat("?,", len(hosts))
		placeholders = placeholders[:len(placeholders)-1]
		stmt += " AND host IN (" + placeholders + ")"
		for _, hh := range hosts {
			args = append(args, hh)
		}
	}
	row := h.DB.QueryRowContext(ctx, stmt, args...)
	var n int
	if err := row.Scan(&n); err != nil {
		log.Printf("countEvents (phase=%q): %v", phase, err)
		return 0
	}
	return n
}

// parseHostFilter: normalize the URL "host" query values as a multi-select.
// Accepts both "host=a&host=b" and "host=a,b".  TrimSpace + drop empties.
func parseHostFilter(raws []string) []string {
	var out []string
	for _, raw := range raws {
		for _, part := range strings.Split(raw, ",") {
			if v := strings.TrimSpace(part); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// resolveHostFilter: resolve the global scope of the host filter.  Precedence:
//  1. unmask_hosts cookie (= written by the shared host_picker.  comma-separated.  empty = all hosts)
//  2. ?host= query param (= deep link / back-compat.  Only when the cookie is unset)
// The host picker uses a cookie like the TZ / language pickers, so the
// selection is preserved across navigation (= one view scope shared by every admin page).
func resolveHostFilter(r *http.Request) []string {
	if c, err := r.Cookie("unmask_hosts"); err == nil {
		if v := decodeCookieValue(c.Value); strings.TrimSpace(v) != "" {
			return parseHostFilter([]string{v})
		}
	}
	return parseHostFilter(r.URL.Query()["host"])
}

// resolveSiteFilter: resolve the single-select site filter shared by every
// admin page.  Precedence mirrors resolveHostFilter: the unmask_site cookie
// (written by the site_picker), then the ?site= query param.  "" = all sites.
func resolveSiteFilter(r *http.Request) string {
	if c, err := r.Cookie("unmask_site"); err == nil {
		if v := strings.TrimSpace(decodeCookieValue(c.Value)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(r.URL.Query().Get("site"))
}
