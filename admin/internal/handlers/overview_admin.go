// /admin/ — top dashboard (= summary page).
//
// Layout:
//   - 4 KPI boxes: events / serves / verify_ok / currently-BANNED, all over the last 24h
//   - 10 most recent detections (= latest unmask_event rows)
//   - shortcuts to each tab (= stats / bot hunt / persistent BAN / settings / docs)
//
// Data source is only the existing events package.  Lightweight.
package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/hll"
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
	// Passed counts split by how the visitor cleared the challenge.  PoW-only
	// is transparent (mostly real browsers); the CAPTCHA paths mean a human
	// solved one.  The old "verify" phase does not exist in native mode.
	kpiPoWPass := countEvents(ctx, h, 1440, "bv_pow_only", site, hosts)
	kpiCaptchaPass := countEventsPhases(ctx, h, 1440,
		[]string{"bv_captcha_only", "bv_pow_then_captcha"}, site, hosts)
	// "Blocked" estimate for the hero: challenges fired that produced no pass
	// (neither PoW nor CAPTCHA) — the visitor hit the wall and never cleared.
	// Not exact (a real user who navigated away counts too, and a serve in the
	// last seconds hasn't had time to pass), but a well-founded figure.
	kpiBlocked := kpiServes - kpiPoWPass - kpiCaptchaPass
	if kpiBlocked < 0 {
		kpiBlocked = 0
	}

	// Non-human traffic %: by *unique client*, not request volume (so one
	// high-volume bot doesn't dominate).  Both figures come from the
	// unmask_traffic_hll HLL sketches written by the nginx-log pipeline:
	//   uTotal   = distinct client IPs over all traffic
	//   uBlocked = distinct IPs challenged but never seen with a pass cookie
	// When the access-log feed is off there is no sketch data → the card
	// shows "—" instead of a misleading 0%.
	uTotal, uBlocked, uKnown := trafficUnique(ctx, h, 1440, site)
	nonHumanPct := 0.0
	if uKnown && uTotal > 0 {
		nonHumanPct = float64(uBlocked) / float64(uTotal) * 100
	}

	// BAN has no host axis (= keyed on the IP+JA4 pair, global).  Same number for every host.
	currentBans := 0
	if h.BanMgr != nil {
		currentBans = len(h.BanMgr.Snapshot())
	}

	// 10 most recent detections (= any phase / id desc).  Fetch 40 raw rows
	// so the client-side session collapse (= same logic as the hunt table:
	// group by beacon_token + collapse into one row showing the phase chain)
	// still has roughly 10 visible sessions in the typical case where one
	// fire contributes 3-5 raw rows.
	recentRaw, err := events.FetchPaged(ctx, h.DB, "", "", "", "", site, hosts, 0, 40, 0)
	if err != nil {
		log.Printf("overview recent: %v", err)
	}
	// IP rendering is unified as "flag + IP + popover" (= same as bans / hunt / dashboard).
	// Tag each row with the IP-geo-looked-up country code + the ban state for the IP.
	// Banned is required by the shared partial_events_table.html partial -- without
	// it the {{ if .Banned }} branch fails template execution and the page truncates
	// at the first row of the recent table.  Same shape as huntEventRow.
	type recentRow struct {
		events.Row
		CountryCode string
		Banned      bool
	}
	geoOK := h.IPGeo != nil && h.IPGeo.Loaded()
	banOK := h.BanMgr != nil
	ccCache := map[string]string{}
	banCache := map[string]bool{}
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
		banned := false
		if banOK && r0.IP != "" {
			if v, ok := banCache[r0.IP]; ok {
				banned = v
			} else {
				banned = h.BanMgr.IsBanned(ctx, r0.IP, "")
				banCache[r0.IP] = banned
			}
		}
		recent = append(recent, recentRow{Row: r0, CountryCode: cc, Banned: banned})
	}

	// AI traffic funnel (= last 24h, top of overview).  Two views on the
	// same crawler taxonomy: "all" reads unmask_crawler_minute (the access-
	// log pipeline that sees rescued / bypassed traffic too), and "served"
	// reads the hkAITag aggregate fed by phase=serve events (= excludes
	// bypassed crawlers, useful for operators who tweaked the rescue
	// presets).  Both run cheap so they share the overview render budget.
	aiRows := aiTrafficSummary(ctx, h, 1440)
	aiDetail := aiTrafficDrilldown(ctx, h, 1440)
	aiServed, _ := dashboard.AITrafficBreakdown(ctx, h.DB, "", nil, 24)
	// Over-block circuit breaker health -- a global signal, so it lives on the
	// landing rather than the per-site stats dashboard.
	overBlock, _ := h.OverBlockHealth(ctx)

	// Hosts / HostSelected / SelfHostID (= for the shared host_picker) are
	// injected by addMeToData, which is shared across every admin page.
	data := map[string]any{
		"Lang":             i18n.Resolve(r),
		"TZ":               resolveTZ(r),
		"KPIEvents":        kpiEvents,
		"KPIServes":        kpiServes,
		"KPIPoWPass":       kpiPoWPass,
		"KPICaptchaPass":   kpiCaptchaPass,
		"KPIBlocked":       kpiBlocked,
		"KPIUniqueTotal":   uTotal,
		"KPIUniqueBlocked": uBlocked,
		"KPINonHumanPct":   nonHumanPct,
		"KPINonHumanKnown": uKnown && uTotal > 0,
		"KPICurrentBans":   currentBans,
		"Recent":           recent,
		// partial_events_table reads .Rows / .EventsCap / .Range so we expose the
		// same recent slice under those keys.  EventsCap=10 caps the client-side
		// visible-session count after the session-collapse pass so the card
		// honours its "10 most recent" heading even though we pre-fetched 40 raw rows.
		"Rows":      recent,
		"EventsCap": 10,
		"Range":     "",
		// Drop the per-row BAN action column on the overview card so the URL /
		// UA columns get the recovered ~4rem of horizontal room.  The hunt page
		// (= the actual deep-dive destination) keeps the action column on.
		"HideActions":     true,
		"AITraffic":       aiRows,
		"AITrafficDetail": aiDetail,
		"AITrafficServed": aiServed,
		"OverBlock":       overBlock,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "overview.html", data); err != nil {
		log.Printf("overview render: %v", err)
	}
}

// AITrafficRow: per-tag aggregation for the overview's crawler funnel.
// Total = every request of that crawler tag; Served = the subset that was
// challenged (= did not pass straight through); Passed = Total - Served.
// Category names follow classify.CrawlerTagOrder (11 tags) so the overview
// + stats cards share one taxonomy.
type AITrafficRow struct {
	Category string // one of classify.CrawlerTagOrder
	Total    int
	Served   int
	Passed   int
}

// aiTrafficSummary reads the last `minutes` of the unmask_crawler_minute
// aggregate (fed by the nginx access-log pipeline / auth_request BumpCrawler).
// This is the only source that sees rescued crawlers — they are passed
// straight through and never recorded in unmask_event.  Global (not scoped by
// the host / site picker; the aggregate has no host dimension).  Best-effort.
func aiTrafficSummary(ctx context.Context, h *Handler, minutes int) []AITrafficRow {
	// Order matches the stats card so the operator's eye doesn't have to
	// re-anchor when switching between views.  Zero-row tags stay visible
	// per the feedback_zero_row_policy.
	byCat := map[string]*AITrafficRow{}
	for _, k := range classify.CrawlerTagOrder {
		byCat[k] = &AITrafficRow{Category: k}
	}
	if h.DB != nil {
		sinceMin := time.Now().Unix()/60 - int64(minutes)
		rows, err := h.DB.QueryContext(ctx,
			`SELECT category, SUM(total), SUM(served) FROM unmask_crawler_minute
			 WHERE bucket_min > ? GROUP BY category`, sinceMin)
		if err != nil {
			log.Printf("aiTrafficSummary: %v", err)
		} else {
			defer rows.Close()
			for rows.Next() {
				var cat string
				var total, served int
				if err := rows.Scan(&cat, &total, &served); err != nil {
					continue
				}
				if r := byCat[cat]; r != nil {
					r.Total = total
					r.Served = served
					r.Passed = total - served
				}
			}
		}
	}
	out := make([]AITrafficRow, 0, len(classify.CrawlerTagOrder))
	for _, k := range classify.CrawlerTagOrder {
		out = append(out, *byCat[k])
	}
	// Sort by Total DESC; ties keep classify.CrawlerTagOrder via stable sort.
	// Zero-row tags fall to the bottom but stay visible (feedback_zero_row_policy).
	sort.SliceStable(out, func(i, j int) bool { return out[i].Total > out[j].Total })
	return out
}

// AICrawlerRow: one individual crawler's traffic within a category, for the
// drill-down popover on the AI/crawler card's "all" tab.  Total = every
// request from that crawler; Served = the subset that was challenged; Passed =
// Total - Served.  Spark is the polyline "points" of a tiny trend sparkline
// (total volume over the window, downsampled), "" when there's nothing to draw.
type AICrawlerRow struct {
	Crawler string
	Total   int
	Served  int
	Passed  int
	Spark   string
}

// aiTrafficDrilldown reads the per-crawler breakdown that backs the card's
// "all"-tab popover, keyed by category (= classify.CrawlerTagOrder).  Source
// is unmask_crawler_detail_hourly -- the same access-log pipeline as
// aiTrafficSummary, resolved one level finer (category -> individual crawler).
//
// It pulls the per-hour rows (not a pre-summed total) so it can also build a
// trend sparkline per crawler: the window's hours are downsampled into ~32
// equal chunks and the per-chunk volume becomes the sparkline.  The chunks are
// label-less (a shape, not dated axes), so they need no operator TZ -- an hour
// is an hour regardless of zone.  Total/Served are the series sums, so the
// popover numbers and the sparkline come from one query.  The lower bound snaps
// down to the containing hour, so the totals never under-count vs the category
// row above.  Only crawlers actually seen produce rows.  Best-effort.
func aiTrafficDrilldown(ctx context.Context, h *Handler, minutes int) map[string][]AICrawlerRow {
	if h.DB == nil {
		return nil
	}
	nowHour := time.Now().Unix() / 3600
	sinceHour := (time.Now().Unix() - int64(minutes)*60) / 3600
	// Downsample the window's hours into ~32 chunks for the sparkline.
	const sparkTarget = 32
	spanHours := nowHour - sinceHour + 1
	if spanHours < 1 {
		spanHours = 1
	}
	chunkHours := (spanHours + sparkTarget - 1) / sparkTarget // ceil
	if chunkHours < 1 {
		chunkHours = 1
	}
	nBuckets := int((spanHours + chunkHours - 1) / chunkHours) // ceil

	rows, err := h.DB.QueryContext(ctx,
		`SELECT category, crawler, bucket_hour, total, served FROM unmask_crawler_detail_hourly
		 WHERE bucket_hour >= ?`, sinceHour)
	if err != nil {
		log.Printf("aiTrafficDrilldown: %v", err)
		return nil
	}
	defer rows.Close()

	type agg struct {
		total, served int
		series        []int
	}
	byKey := map[[2]string]*agg{} // {category, crawler} -> agg
	for rows.Next() {
		var cat, crawler string
		var bucketHour int64
		var total, served int
		if err := rows.Scan(&cat, &crawler, &bucketHour, &total, &served); err != nil {
			continue
		}
		if total <= 0 {
			continue
		}
		k := [2]string{cat, crawler}
		a := byKey[k]
		if a == nil {
			a = &agg{series: make([]int, nBuckets)}
			byKey[k] = a
		}
		a.total += total
		a.served += served
		if bi := int((bucketHour - sinceHour) / chunkHours); bi >= 0 && bi < nBuckets {
			a.series[bi] += total
		}
	}

	byCat := map[string][]AICrawlerRow{}
	for k, a := range byKey {
		byCat[k[0]] = append(byCat[k[0]], AICrawlerRow{
			Crawler: k[1], Total: a.total, Served: a.served, Passed: a.total - a.served,
			Spark: sparkPoints(a.series),
		})
	}
	// Per-category: Total DESC, then crawler name ASC for a stable, readable
	// order (map-scan order is otherwise non-deterministic).
	for cat := range byCat {
		list := byCat[cat]
		sort.Slice(list, func(i, j int) bool {
			if list[i].Total != list[j].Total {
				return list[i].Total > list[j].Total
			}
			return list[i].Crawler < list[j].Crawler
		})
	}
	return byCat
}

// sparkPoints renders a series of per-chunk counts as the "points" attribute of
// an SVG <polyline> in a 64x16 box (1px inset so the stroke stays inside).  The
// y-axis is anchored at 0 and scaled to the series max, so a crawler that ramped
// from nothing reads as a clear rise.  Returns "" when there's nothing to draw
// (fewer than 2 points, or all-zero).
func sparkPoints(series []int) string {
	n := len(series)
	if n < 2 {
		return ""
	}
	max := 0
	for _, v := range series {
		if v > max {
			max = v
		}
	}
	if max <= 0 {
		return ""
	}
	const w, h, pad = 64.0, 16.0, 1.0
	uw, uh := w-2*pad, h-2*pad
	var b strings.Builder
	for i, v := range series {
		x := pad + float64(i)/float64(n-1)*uw
		y := pad + (1-float64(v)/float64(max))*uh
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String()
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

// countEventsPhases: like countEvents but matches any of several phases
// (phase IN (...)).  Used for the "passed" KPIs, which span multiple terminal
// bv_* phases.  Best-effort (= on error, return 0 and just log).
func countEventsPhases(ctx context.Context, h *Handler, minutes int, phases []string, site string, hosts []string) int {
	stmt := `SELECT COUNT(*) FROM unmask_event WHERE date_created > ` + h.DB.NowMinusMinutes(minutes)
	args := []any{}
	if len(phases) > 0 {
		ph := strings.Repeat("?,", len(phases))
		stmt += " AND phase IN (" + ph[:len(ph)-1] + ")"
		for _, p := range phases {
			args = append(args, p)
		}
	}
	if site != "" {
		stmt += " AND site = ?"
		args = append(args, site)
	}
	if len(hosts) > 0 {
		ph := strings.Repeat("?,", len(hosts))
		stmt += " AND host IN (" + ph[:len(ph)-1] + ")"
		for _, hh := range hosts {
			args = append(args, hh)
		}
	}
	row := h.DB.QueryRowContext(ctx, stmt, args...)
	var n int
	if err := row.Scan(&n); err != nil {
		log.Printf("countEventsPhases (%v): %v", phases, err)
		return 0
	}
	return n
}

// trafficUnique: unique-client figures over the last <minutes>, merged from
// the unmask_traffic_hll HLL sketches written by the nginx-log pipeline.
//
//	total   = distinct client IPs across all traffic
//	blocked = distinct IPs that were challenged but never seen carrying a
//	          pass cookie  (= est(ipc ∪ ipp) − est(ipp))
//	known   = false when there is no sketch data at all (= the access-log
//	          feed is off, or the feature was just deployed) → caller shows "—"
//
// Best-effort: on a query error returns known=false.
func trafficUnique(ctx context.Context, h *Handler, minutes int, site string) (total, blocked int, known bool) {
	cutoff := time.Now().Unix()/60 - int64(minutes)
	stmt := `SELECT kind, sketch FROM unmask_traffic_hll WHERE bucket_min >= ?`
	args := []any{cutoff}
	if site != "" {
		stmt += " AND site = ?"
		args = append(args, site)
	}
	rows, err := h.DB.QueryContext(ctx, stmt, args...)
	if err != nil {
		log.Printf("trafficUnique: %v", err)
		return 0, 0, false
	}
	defer rows.Close()
	merged := map[string]*hll.Sketch{} // kind -> window-merged sketch
	for rows.Next() {
		var kind string
		var blob []byte
		if err := rows.Scan(&kind, &blob); err != nil {
			log.Printf("trafficUnique scan: %v", err)
			return 0, 0, false
		}
		s := merged[kind]
		if s == nil {
			s = &hll.Sketch{}
			merged[kind] = s
		}
		s.Merge(hll.Load(blob))
	}
	if err := rows.Err(); err != nil {
		log.Printf("trafficUnique rows: %v", err)
		return 0, 0, false
	}
	ipAll := merged["ip"]
	if ipAll == nil {
		return 0, 0, false // no sketch data
	}
	total = ipAll.Estimate()
	if ipChal := merged["ipc"]; ipChal != nil {
		// blocked = challenged minus those that ever passed.  HLL has no
		// subtraction, so est(ipc \ ipp) = est(ipc ∪ ipp) − est(ipp).
		union := &hll.Sketch{}
		union.Merge(ipChal)
		passEst := 0
		if ipPass := merged["ipp"]; ipPass != nil {
			union.Merge(ipPass)
			passEst = ipPass.Estimate()
		}
		blocked = union.Estimate() - passEst
		if blocked < 0 {
			blocked = 0
		}
	}
	return total, blocked, true
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
//  2. ?host= query param (= deep link.  Only when the cookie is unset)
//
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

// siteFilterRE: a site filter value is a hostname-ish token.  Validate at the
// source (defense in depth) so a hostile unmask_site cookie / ?site= can never
// reach a SQL sink even if one forgets siteCond (= the 2026-06 SQLi via three
// dashboard queries that hand-rolled `site = '<raw>'`).
var siteFilterRE = regexp.MustCompile(`^[a-z0-9.:_-]+$`)

func sanitizeSiteFilter(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || !siteFilterRE.MatchString(v) {
		return ""
	}
	return v
}

// resolveSiteFilter: resolve the single-select site filter shared by every
// admin page.  Precedence mirrors resolveHostFilter: the unmask_site cookie
// (written by the site_picker), then the ?site= query param.  "" = all sites.
func resolveSiteFilter(r *http.Request) string {
	if c, err := r.Cookie("unmask_site"); err == nil {
		if v := sanitizeSiteFilter(decodeCookieValue(c.Value)); v != "" {
			return v
		}
	}
	return sanitizeSiteFilter(r.URL.Query().Get("site"))
}
