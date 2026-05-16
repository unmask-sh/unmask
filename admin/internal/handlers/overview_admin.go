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
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

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

	// Last-24h KPIs.  On failure, fall through with 0.
	kpiEvents := countEvents(ctx, h, 1440, "", hosts)
	kpiServes := countEvents(ctx, h, 1440, "serve", hosts)
	kpiVerify := countEvents(ctx, h, 1440, "verify", hosts)

	// BAN has no host axis (= keyed on the IP+JA4 pair, global).  Same number for every host.
	currentBans := 0
	if h.BanMgr != nil {
		currentBans = len(h.BanMgr.Snapshot())
	}

	// 5 most recent detections (= any phase / id desc).
	recentRaw, err := events.FetchPaged(ctx, h.DB, "", "", "", hosts, 0, 5, 0)
	if err != nil {
		log.Printf("overview recent: %v", err)
	}
	// IP rendering is unified as "flag + IP + popover" (= same as bans / hunt / dashboard).
	// Tag each row with the GeoIP-looked-up country code.  Leave empty if GeoIP is not loaded.
	type recentRow struct {
		events.Row
		CountryCode string
	}
	geoOK := h.GeoIP != nil && h.GeoIP.Loaded()
	ccCache := map[string]string{}
	recent := make([]recentRow, 0, len(recentRaw))
	for _, r0 := range recentRaw {
		cc := ""
		if geoOK && r0.IP != "" {
			if v, ok := ccCache[r0.IP]; ok {
				cc = v
			} else {
				cc = h.GeoIP.LookupInfo(r0.IP).Country
				ccCache[r0.IP] = cc
			}
		}
		recent = append(recent, recentRow{Row: r0, CountryCode: cc})
	}

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
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "overview.html", data); err != nil {
		log.Printf("overview render: %v", err)
	}
}

// countEvents: count of unmask_event rows in the last `minutes`.  Empty phase
// means all rows.  Non-empty hosts narrows via IN (...) for multi-host filtering.
// Best-effort (= on error, return 0 and just log).
func countEvents(ctx context.Context, h *Handler, minutes int, phase string, hosts []string) int {
	stmt := `SELECT COUNT(*) FROM unmask_event WHERE date_created > ` + h.DB.NowMinusMinutes(minutes)
	args := []any{}
	if phase != "" {
		stmt += " AND phase = ?"
		args = append(args, phase)
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
	if c, err := r.Cookie("unmask_hosts"); err == nil && strings.TrimSpace(c.Value) != "" {
		return parseHostFilter([]string{c.Value})
	}
	return parseHostFilter(r.URL.Query()["host"])
}
