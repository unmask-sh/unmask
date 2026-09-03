// Persistent BAN tab: management screen for shared infrastructure used by
// multiple features (= honeypot / manual / future protected_failed etc.).
// admin role or higher can view / operate.
//
// Dispatch by op parameter:
//
//	op=add              : manual add with ip + ja4 + reason + duration_sec
//	op=delete           : unban by id
//	op=subscribe-toggle : turn the community bans subscribe (= pull) ON/OFF.  Top-right toggle only
//
// The honeypot-derived default TTL (= ban_duration) has been moved to settings/honeypot/.
// Detailed community-bans settings (terms / submit / URL override etc.) live in settings/community-bans/.
// The bans page is intentionally a shortcut UX that triggers only **subscribe (= receive)**.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// AdminBansIndex: GET /admin/bans/ — BAN list + manual-add form + community-bans browse.
func (h *Handler) AdminBansIndex(w http.ResponseWriter, r *http.Request) {
	if h.BanMgr == nil {
		http.Error(w, "ban manager not configured", http.StatusInternalServerError)
		return
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	entries := h.BanMgr.Snapshot()

	// Look up the country code so we can render the flag to the left of the
	// IP popover (= rDNS + IP-geo).  Cache per-IP in a map to avoid duplicate
	// lookups.  Leave empty if IP-geo is not loaded.
	type banRow struct {
		ban.Entry
		CountryCode string
		// ResolvedAction is the action that actually applies once
		// Entry.Action falls back via BansConfig.ResolveAction.  Surfaced
		// in the list view so "(default)" rows still tell the operator
		// what's going to happen.
		ResolvedAction string
	}
	ipCC := map[string]string{}
	lookupCC := func(ip string) string {
		if ip == "" || h.IPGeo == nil || !h.IPGeo.Loaded() {
			return ""
		}
		if cc, ok := ipCC[ip]; ok {
			return cc
		}
		cc := h.IPGeo.LookupInfo(ip).Country
		ipCC[ip] = cc
		return cc
	}
	banRows := make([]banRow, 0, len(entries))
	bansCfg := h.cfg().Nginx.Bans
	honeyDefault := h.cfg().Nginx.Honeypot.DefaultAction
	for _, e := range entries {
		resolved := strings.TrimSpace(e.Action)
		if resolved == "" {
			resolved = bansCfg.ResolveAction(e.Source, honeyDefault)
		}
		banRows = append(banRows, banRow{Entry: e, CountryCode: lookupCC(e.IP), ResolvedAction: resolved})
	}

	// === community-bans browse: migrated from /admin/community-bans/ ===
	cur := h.snapshotSettings()
	mapDir := strings.TrimSpace(cur.CommunityBans.MapDir)
	if mapDir == "" {
		mapDir = strings.TrimSpace(cur.Nginx.OutputDir)
	}
	if mapDir == "" {
		mapDir = "/var/lib/unmask/nginx"
	}
	var doc communitybans.FeedDocument
	if h.CommunityBans != nil {
		doc = h.CommunityBans.GetCachedDoc()
	}
	match := strings.TrimSpace(r.URL.Query().Get("match"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	// FeedEntry + CountryCode (= for the flag rendered to the left of the IP popover).
	type feedRow struct {
		communitybans.FeedEntry
		CountryCode string
		Bypassed    bool // IP sits in a bypass range -> exempt from enforcement
	}
	bypass := communitybans.NewBypassMatcher(cur)
	filtered := make([]feedRow, 0, len(doc.Entries))
	for _, e := range doc.Entries {
		if match != "" && string(e.Match) != match {
			continue
		}
		if q != "" {
			hay := e.IP + " " + e.JA4 + " " + e.Reason
			for _, c := range e.Comments {
				hay += " " + c.Text
			}
			if !strings.Contains(strings.ToLower(hay), strings.ToLower(q)) {
				continue
			}
		}
		filtered = append(filtered, feedRow{FeedEntry: e, CountryCode: lookupCC(e.IP), Bypassed: bypass.Match(e.IP)})
	}
	var countIPJA4, countJA4, countIP int
	for _, e := range doc.Entries {
		switch e.Match {
		case communitybans.MatchIPJA4:
			countIPJA4++
		case communitybans.MatchJA4:
			countJA4++
		case communitybans.MatchIPOnly:
			countIP++
		}
	}

	// Effective HN: override wins (= what other installs see), with cached
	// derived hn as fallback.  Both are kept in settings so the user can
	// drop the override and revert without re-registering.
	myHN := strings.TrimSpace(cur.CommunityBans.HNOverride)
	if myHN == "" {
		myHN = strings.TrimSpace(cur.CommunityBans.HN)
	}

	// BAN source breakdown -- powers the "Community Bans 効果" card.
	// We compute from banRows (= the live snapshot) so the figures match
	// what the operator sees in the BAN table directly above.
	sourceCounts := make(map[string]int, 4)
	for _, br := range banRows {
		s := strings.TrimSpace(br.Source)
		if s == "" {
			s = "manual"
		}
		sourceCounts[s]++
	}
	type sourcePill struct {
		Source string
		Count  int
		Pct    int
	}
	totalBans := len(banRows)
	sourceOrder := []string{"community_bans", "honeypot", "manual"}
	sourcePills := make([]sourcePill, 0, len(sourceOrder))
	for _, s := range sourceOrder {
		n := sourceCounts[s]
		pct := 0
		if totalBans > 0 {
			pct = int((float64(n)*100 + 0.5) / float64(totalBans))
		}
		sourcePills = append(sourcePills, sourcePill{Source: s, Count: n, Pct: pct})
	}

	// NOTE: the "Community Bans impact" 30-day figures are deliberately NOT
	// computed here -- bans.html never rendered them, and the query scans the
	// whole 30-day serve window (measured 5s on a fleet DB).  The community
	// tab (AdminCommunityBansIndex) shows them via the communityHits cache.
	data := map[string]any{
		"Lang":                      i18n.Resolve(r),
		"TZ":                        resolveTZ(r),
		"BasePath":                  h.cfg().Server.BasePath,
		"Version":                   h.Version,
		"Entries":                   banRows,
		"BanFilePath":               h.cfg().Nginx.Honeypot.BanFilePath,
		"Bans":                      h.cfg().Nginx.Bans,
		"Saved":                     r.URL.Query().Get("saved") != "",
		"Error":                     readFlash(w, r, h.cfg().Server.BasePath, "err"),
		"SubscribeMode":             cur.CommunityBans.ResolvedSubscribeMode(),
		"MyHN":                      myHN,
		"SourcePills":               sourcePills,
		"CommunityBansFromHub":      sourceCounts["community_bans"],
		"CommunityBansLastPulledAt": cur.CommunityBans.LastPulledAt,
		"CommunityBansGeneratedAt":  doc.GeneratedAt,
		"CommunityBansVersion":      doc.Version,
		"CommunityBansEntries":      filtered,
		"CommunityBansTotalEntries": len(doc.Entries),
		"CommunityBansFiltered":     len(filtered),
		"CommunityBansCountIPJA4":   countIPJA4,
		"CommunityBansCountJA4":     countJA4,
		"CommunityBansCountIP":      countIP,
		"CommunityBansMatch":        match,
		"CommunityBansQuery":        q,
		"CommunityBansMapDir":       mapDir,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "bans.html", data); err != nil {
		log.Printf("bans render: %v", err)
	}
}

// AdminCommunityBansIndex: GET /admin/community-bans/{$} — dedicated browse
// page for the hub feed.  Was an inline card on /admin/bans/ until v2
// landed; with 100+ rows expected per install, split into its own tab so
// the BAN management table stays compact and the community list can
// paginate / filter without crowding the rest of the page.
//
// Pagination: ?page=N, 50 entries per page.  Filtering (= ?q, ?match)
// applies before pagination so navigating pages keeps the filter window.
func (h *Handler) AdminCommunityBansIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cur := h.snapshotSettings()
	mapDir := strings.TrimSpace(cur.CommunityBans.MapDir)
	if mapDir == "" {
		mapDir = strings.TrimSpace(cur.Nginx.OutputDir)
	}
	if mapDir == "" {
		mapDir = "/var/lib/unmask/nginx"
	}
	var doc communitybans.FeedDocument
	if h.CommunityBans != nil {
		doc = h.CommunityBans.GetCachedDoc()
	}

	ipCC := map[string]string{}
	lookupCC := func(ip string) string {
		if ip == "" || h.IPGeo == nil || !h.IPGeo.Loaded() {
			return ""
		}
		if cc, ok := ipCC[ip]; ok {
			return cc
		}
		cc := h.IPGeo.LookupInfo(ip).Country
		ipCC[ip] = cc
		return cc
	}

	match := strings.TrimSpace(r.URL.Query().Get("match"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	type feedRow struct {
		communitybans.FeedEntry
		CountryCode string
		Bypassed    bool // IP sits in a bypass range -> exempt from enforcement
	}
	bypass := communitybans.NewBypassMatcher(cur)
	filtered := make([]feedRow, 0, len(doc.Entries))
	for _, e := range doc.Entries {
		if match != "" && string(e.Match) != match {
			continue
		}
		if q != "" {
			hay := e.IP + " " + e.JA4 + " " + e.Reason
			for _, c := range e.Comments {
				hay += " " + c.Text
			}
			if !strings.Contains(strings.ToLower(hay), strings.ToLower(q)) {
				continue
			}
		}
		filtered = append(filtered, feedRow{FeedEntry: e, CountryCode: lookupCC(e.IP), Bypassed: bypass.Match(e.IP)})
	}

	var countIPJA4, countJA4, countIP int
	for _, e := range doc.Entries {
		switch e.Match {
		case communitybans.MatchIPJA4:
			countIPJA4++
		case communitybans.MatchJA4:
			countJA4++
		case communitybans.MatchIPOnly:
			countIP++
		}
	}

	// Sorting -- ?sort=KEY&order=asc|desc.  Default sort: score desc, tie-broken
	// by report count desc + first-seen desc for stable ordering.  Unknown
	// keys fall back to the default so a bookmarked URL with a typo still
	// renders.  Numeric keys default to desc (= "biggest first", which is
	// what you almost always want on a ranking-style table).
	sortKey := strings.TrimSpace(r.URL.Query().Get("sort"))
	switch sortKey {
	case "score", "reports", "good", "bad", "comments", "first_seen", "last_seen", "expires":
		// keep
	default:
		sortKey = "score"
	}
	orderParam := strings.TrimSpace(r.URL.Query().Get("order"))
	desc := orderParam != "asc" // default desc unless explicitly asc
	sort.SliceStable(filtered, func(i, j int) bool {
		a, b := filtered[i], filtered[j]
		var less bool
		switch sortKey {
		case "score":
			less = a.Score < b.Score
		case "reports":
			less = a.Reports < b.Reports
		case "good":
			less = a.LikeCount < b.LikeCount
		case "bad":
			less = a.BadCount < b.BadCount
		case "comments":
			less = a.CommentCount < b.CommentCount
		case "first_seen":
			less = a.FirstSeen < b.FirstSeen
		case "last_seen":
			// FeedEntry has no LastSeen field; use ExpiresAt - 30 days as a
			// proxy (= ExpiresAt is LastSeen + retention).
			less = a.ExpiresAt < b.ExpiresAt
		case "expires":
			less = a.ExpiresAt < b.ExpiresAt
		}
		if desc {
			return !less
		}
		return less
	})

	// Pagination -- 50 rows per page, 1-indexed.  Out-of-range pages clamp
	// to the last available page so a bookmarked URL still renders.
	const perPage = 50
	page := 1
	if v, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page"))); err == nil && v >= 1 {
		page = v
	}
	total := len(filtered)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * perPage
	end := start + perPage
	if end > total {
		end = total
	}
	pageRows := []feedRow{}
	if start < total {
		pageRows = filtered[start:end]
	}

	myHN := strings.TrimSpace(cur.CommunityBans.HNOverride)
	if myHN == "" {
		myHN = strings.TrimSpace(cur.CommunityBans.HN)
	}

	// "Community Bans 効果": past-30d block count from unmask_event (= traffic
	// that hub-derived BANs actually stopped on this install).  Served from
	// the communityHits TTL cache -- the query scans the whole 30-day serve
	// window and must not run per page load (see community_hits.go).  When no
	// figure is known yet the template renders an em dash, never a fake zero.
	hitStats, hitsKnown, hitsComputing := h.communityHitsFigure()
	var hitsFromHub int
	if h.DB != nil {
		// Rows currently in the local BAN list sourced from the hub (= shown
		// next to the past-30d hits as "rows copied from the hub").  unmask_ban
		// is small (the live ban list), so this stays a direct query.
		_ = h.DB.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM unmask_ban WHERE source = 'community_bans'`).Scan(&hitsFromHub)
	}

	// "Next fetch" estimate: the pull loop re-fetches every
	// communitybans.PullInterval (fixed), updating LastPulledAt only on a
	// *successful* pull -- so the next fetch lands ~one interval after the last
	// success.  Shown only when subscribe is active and we have pulled at least
	// once (0 -> the template hides the line).
	var nextPullAt int64
	if cur.CommunityBans.SubscribeActive() && cur.CommunityBans.LastPulledAt > 0 {
		nextPullAt = cur.CommunityBans.LastPulledAt + int64(communitybans.PullInterval.Seconds())
	}

	data := map[string]any{
		"Lang":                         i18n.Resolve(r),
		"TZ":                           resolveTZ(r),
		"BasePath":                     h.cfg().Server.BasePath,
		"Version":                      h.Version,
		"SubscribeMode":                cur.CommunityBans.ResolvedSubscribeMode(),
		"MyHN":                         myHN,
		"CommunityBansEntries":         pageRows,
		"CommunityBansTotalEntries":    len(doc.Entries),
		"CommunityBansFiltered":        total,
		"CommunityBansCountIPJA4":      countIPJA4,
		"CommunityBansCountJA4":        countJA4,
		"CommunityBansCountIP":         countIP,
		"CommunityBansLastPulledAt":    cur.CommunityBans.LastPulledAt,
		"CommunityBansGeneratedAt":     doc.GeneratedAt,
		"CommunityBansVersion":         doc.Version,
		"CommunityBansNextPullAt":      nextPullAt,
		"CommunityBansHits30d":         hitStats.Count,
		"CommunityBansHitsUniqueIP30d": hitStats.UniqueIP,
		"CommunityBansHitsKnown":       hitsKnown,
		// Computing: the figure is not known yet but a background scan is in
		// flight, so the template shows a spinner ("computing…") instead of a
		// bare em dash (which reads as "no data").  The page's JS polls
		// /admin/api/community-bans/impact and swaps in the number when it lands.
		"CommunityBansHitsComputing": hitsComputing,
		"CommunityBansFromHub":       hitsFromHub,
		"CommunityBansMatch":         match,
		"CommunityBansQuery":         q,
		"CommunityBansMapDir":        mapDir,
		"CommunityBansSort":          sortKey,
		"CommunityBansOrder":         orderParam,
		"Page":                       page,
		"PageNext":                   page + 1,
		"PagePrev":                   page - 1,
		"TotalPages":                 totalPages,
		"PerPage":                    perPage,
		"PageStart":                  start + 1,
		"PageEnd":                    end,
		"Pager": buildPagerData(
			i18n.Resolve(r),
			page, totalPages, perPage, total,
			buildBansBaseURL(q, match, sortKey, orderParam),
		),
		// MutedKeys: presence of a feed entry's MuteKey here means this
		// install has opted out (= LocalMutes); the row should render a
		// "muted" badge and an "unmute" toggle instead of "mute".
		"MutedKeys": muteLookupForTemplate(cur.CommunityBans.LocalMutes),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "community_bans.html", data); err != nil {
		log.Printf("community-bans render: %v", err)
	}
}

// communityHitsFigure returns the cached 30-day Community Bans impact figure,
// whether it is known yet, and whether a background computation is in flight.
// Shared by the page render and the impact-poll JSON endpoint.  The compute is
// always dispatched to the background (community_hits.go), so this never blocks
// on the 30-day scan.
func (h *Handler) communityHitsFigure() (communityHitStats, bool, bool) {
	if h.DB == nil {
		return communityHitStats{}, false, false
	}
	stats, known := h.communityHits.get(time.Now(), func() (communityHitStats, error) {
		// Background-safe: independent of the request context so a page abort
		// can't kill the refresh half-way.
		return communityBansHits30d(context.Background(), h.DB)
	})
	return stats, known, !known && h.communityHits.Refreshing()
}

// AdminCommunityBansImpact: GET /admin/api/community-bans/impact — the 30-day
// impact figure as JSON.  The community-bans page polls this while the
// background scan runs so the spinner resolves into the number without a manual
// reload; each poll also nudges a stalled computation back to life (a not-known,
// not-refreshing state re-dispatches the background scan).
func (h *Handler) AdminCommunityBansImpact(w http.ResponseWriter, r *http.Request) {
	stats, known, computing := h.communityHitsFigure()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"known":     known,
		"computing": computing,
		"count":     stats.Count,
		"uniqueIP":  stats.UniqueIP,
	})
}

// AdminCommunityBansDetail: GET /admin/api/community-bans/detail?ip=...&ja4=...
//
// Thin proxy to the hub's public /api/feed/aggregate endpoint.  The hub
// endpoint is open by design (= raw signals are intentionally public so users
// can audit verdicts), but the admin still proxies it so:
//
//  1. the browser only talks to its own admin origin (= avoids a CORS round-trip)
//  2. the operator can point CommunityBans.AggregateURL at a custom hub
//     without touching the front-end
//  3. local debugging works behind networks that block the public hub
//
// Returns the hub JSON body verbatim with a short cache header so a busy
// expand-collapse loop doesn't hammer the hub.
func (h *Handler) AdminCommunityBansDetail(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	ja4 := strings.TrimSpace(r.URL.Query().Get("ja4"))
	if ip == "" && ja4 == "" {
		http.Error(w, "ip or ja4 is required", http.StatusBadRequest)
		return
	}
	cur := h.snapshotSettings()
	base := strings.TrimRight(cur.CommunityBans.ResolvedAggregateURL(), "?&")
	q := url.Values{}
	if ip != "" {
		q.Set("ip", ip)
	}
	if ja4 != "" {
		q.Set("ja4", ja4)
	}
	target := base + "?" + q.Encode()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("User-Agent", "unmask/"+h.Version+" community-bans-detail-proxy")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("bans: aggregate proxy: %v", err)
		http.Error(w, "hub unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=15")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// resolveHubAPIBase: derive the hub /api/feed/ base from the RegisterURL the
// install is pinned to.  Stripping the last path segment lets the operator
// keep one URL field for /api/feed/* and not maintain a parallel constant per
// endpoint -- the hub always exposes vote / comment / submission siblings of
// register on the same base.
func resolveHubAPIBase(register string) string {
	if i := strings.LastIndex(register, "/"); i > 0 {
		return register[:i]
	}
	return register
}

// proxyToHub: forward an admin request to a hub URL with the install's bearer
// token attached.  Body is copied verbatim; the response is streamed back so
// the caller does not need to materialize the full payload.  Errors short-
// circuit with 502 (= hub unreachable) or 401 (= no install token yet).
func (h *Handler) proxyToHub(w http.ResponseWriter, r *http.Request, target string, withBody bool) {
	cur := h.snapshotSettings()
	token := strings.TrimSpace(cur.CommunityBans.Token)
	if token == "" {
		http.Error(w, "community-bans token not registered yet", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var body io.Reader
	if withBody {
		body = http.MaxBytesReader(nil, r.Body, 16*1024) // 16 KiB hard cap
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target, body)
	if err != nil {
		http.Error(w, "build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if withBody {
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/json"
		}
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("User-Agent", "unmask/"+h.Version+" community-bans-proxy")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("bans: hub proxy %s: %v", target, err)
		http.Error(w, "hub unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// muteLookupForTemplate: build a map[string]bool the template can use as a
// set lookup ({{ index .MutedKeys $key }}).  Blank entries are dropped.
func muteLookupForTemplate(mutes []string) map[string]bool {
	if len(mutes) == 0 {
		return nil
	}
	out := make(map[string]bool, len(mutes))
	for _, m := range mutes {
		m = strings.TrimSpace(m)
		if m != "" {
			out[m] = true
		}
	}
	return out
}

// AdminCommunityBansMuteToggle: POST /admin/community-bans/mute-toggle
//
//	form: key=<MuteKey>   action=mute | unmute
//
// Local-only override: flips an entry on / off in
// settings.CommunityBans.LocalMutes without touching the hub.  Next pull
// rebuilds the map files; for immediate effect we also trigger an
// out-of-band re-pull via the existing pull cycle goroutine.  Roles:
// admin / superadmin only.
func (h *Handler) AdminCommunityBansMuteToggle(w http.ResponseWriter, r *http.Request) {
	pay := SessionFromContext(r)
	if pay == nil || !user.CanWrite(pay.Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(r.FormValue("key"))
	action := strings.TrimSpace(r.FormValue("action"))
	if key == "" || (action != "mute" && action != "unmute") {
		http.Error(w, "key + action=mute|unmute required", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		http.Error(w, "load: "+err.Error(), http.StatusInternalServerError)
		return
	}
	mutes := cur.CommunityBans.LocalMutes
	seen := make(map[string]bool, len(mutes))
	out := mutes[:0]
	for _, m := range mutes {
		m = strings.TrimSpace(m)
		if m == "" || seen[m] {
			continue
		}
		if m == key && action == "unmute" {
			continue // drop this entry
		}
		seen[m] = true
		out = append(out, m)
	}
	if action == "mute" && !seen[key] {
		out = append(out, key)
	}
	cur.CommunityBans.LocalMutes = out
	if err := settings.Save(cur, h.ConfigPath); err != nil {
		http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	settingsMu.Lock()
	h.settingsPtr.Store(&cur)
	settingsMu.Unlock()
	if h.UserRepo != nil {
		username := ""
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			username = u.Username
		}
		h.UserRepo.Record(r.Context(), pay.UserID, username, "community_bans_"+action,
			key, "")
	}
	// Best-effort: trigger an immediate map re-render so the new mute takes
	// effect without waiting for the next 1h pull cycle.  Failures only delay
	// enforcement until the scheduled pull -- they don't break the save.
	if h.CommunityBans != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := h.CommunityBans.Pull(ctx); err != nil {
				log.Printf("communitybans: immediate re-pull after mute toggle: %v", err)
			}
		}()
	}
	http.Redirect(w, r, base+"/admin/community-bans/", http.StatusFound)
}

// AdminCommunityBansVote: POST /admin/api/community-bans/vote
//
//	body: {"submission_id": int, "kind": "like" | "bad"}
//
// Forwards to the hub /api/feed/vote endpoint with the install's bearer
// token.  Hub UPSERTs the vote (= switching like -> bad reuses the same row).
func (h *Handler) AdminCommunityBansVote(w http.ResponseWriter, r *http.Request) {
	cur := h.snapshotSettings()
	base := resolveHubAPIBase(cur.CommunityBans.ResolvedRegisterURL())
	h.proxyToHub(w, r, base+"/vote", true)
}

// AdminCommunityBansVoteDelete: DELETE /admin/api/community-bans/vote/{id}
func (h *Handler) AdminCommunityBansVoteDelete(w http.ResponseWriter, r *http.Request) {
	cur := h.snapshotSettings()
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	base := resolveHubAPIBase(cur.CommunityBans.ResolvedRegisterURL())
	h.proxyToHub(w, r, base+"/vote/"+url.PathEscape(id), false)
}

// AdminCommunityBansComment: POST /admin/api/community-bans/comment
//
//	body: {"submission_id": int, "text": "..."}
func (h *Handler) AdminCommunityBansComment(w http.ResponseWriter, r *http.Request) {
	cur := h.snapshotSettings()
	base := resolveHubAPIBase(cur.CommunityBans.ResolvedRegisterURL())
	h.proxyToHub(w, r, base+"/comment", true)
}

// AdminCommunityBansCommentDelete: DELETE /admin/api/community-bans/comment/{id}
func (h *Handler) AdminCommunityBansCommentDelete(w http.ResponseWriter, r *http.Request) {
	cur := h.snapshotSettings()
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	base := resolveHubAPIBase(cur.CommunityBans.ResolvedRegisterURL())
	h.proxyToHub(w, r, base+"/comment/"+url.PathEscape(id), false)
}

// AdminCommunityBansMySubmissions: GET /admin/api/community-bans/me/submissions
//
// Bearer-forwarded proxy that returns every row owned by this install's
// token -- the operator's own BAN reports, comments, and votes.  Powers the
// "自分の submit 一覧" panel on the bans page (= GDPR Art 15 surface).
func (h *Handler) AdminCommunityBansMySubmissions(w http.ResponseWriter, r *http.Request) {
	cur := h.snapshotSettings()
	base := resolveHubAPIBase(cur.CommunityBans.ResolvedRegisterURL())
	h.proxyToHub(w, r, base+"/me/submissions", false)
}

// AdminCommunityBansSubmissionDelete: DELETE /admin/api/community-bans/submission/{id}
func (h *Handler) AdminCommunityBansSubmissionDelete(w http.ResponseWriter, r *http.Request) {
	cur := h.snapshotSettings()
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	base := resolveHubAPIBase(cur.CommunityBans.ResolvedRegisterURL())
	h.proxyToHub(w, r, base+"/submission/"+url.PathEscape(id), false)
}

// AdminBansSave: POST /admin/bans/save — dispatch by op parameter.
func (h *Handler) AdminBansSave(w http.ResponseWriter, r *http.Request) {
	if h.BanMgr == nil {
		http.Error(w, "ban manager not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	// return_to lets a form posted from a different page (= the subscribe
	// toggle lives on both /admin/bans/ and /admin/community-bans/) come
	// back to where it was submitted.  Whitelist to known admin sub-paths
	// so the field can't be turned into an open redirect.
	returnTo := base + "/admin/bans/"
	switch strings.TrimSpace(r.FormValue("return_to")) {
	case "community-bans":
		returnTo = base + "/admin/community-bans/"
	case "advisor":
		returnTo = base + "/admin/advisor/"
	case "bans", "":
		returnTo = base + "/admin/bans/"
	}
	redir := func(msg string) {
		dst := returnTo
		if msg == "" {
			dst += "?saved=1"
		} else {
			setFlash(w, r, base, "err", msg)
		}
		http.Redirect(w, r, dst, http.StatusFound)
	}

	pay := SessionFromContext(r)
	if pay == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	meUsername := ""
	if me, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
		meUsername = me.Username
	}

	op := r.FormValue("op")
	switch op {
	case "add":
		ip := strings.TrimSpace(r.FormValue("ip"))
		ja4 := strings.TrimSpace(r.FormValue("ja4"))
		scope := strings.TrimSpace(r.FormValue("scope"))
		reason := strings.TrimSpace(r.FormValue("reason"))
		durSec, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("duration_sec")), 10, 64)
		// Per-row action override.  Empty / unknown drops back to
		// settings.Bans.ManualDefaultAction at flush time.  Field name is
		// "ban_action" (not "action") so it does not shadow the form's
		// action property in the DOM, which other JS code may rely on.
		action := strings.TrimSpace(r.FormValue("ban_action"))
		if action != "" && !settings.IsValidRateChallengeMode(action) {
			action = ""
		}
		if ip == "" && ja4 == "" {
			redir("ip or ja4 is required")
			return
		}
		if err := h.BanMgr.AddManualWithScope(r.Context(), ip, ja4, scope, reason, meUsername, action, durSec); err != nil {
			redir("add: " + err.Error())
			return
		}
		if h.UserRepo != nil {
			h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "ban_add",
				fmt.Sprintf("%s|%s", ip, ja4),
				fmt.Sprintf(`{"reason":%q,"duration_sec":%d}`, reason, durSec))
		}
		redir("")
		return

	case "delete":
		id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
		if err != nil || id <= 0 {
			redir("invalid id")
			return
		}
		if err := h.BanMgr.Remove(r.Context(), id); err != nil {
			redir("unban: " + err.Error())
			return
		}
		if h.UserRepo != nil {
			h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "ban_remove",
				strconv.FormatInt(id, 10), "")
		}
		redir("")
		return

	case "edit":
		// Inline edit of an existing manual BAN row -- the dialog opened
		// from the row's 「編集」 button posts here.  Match scope (= IP+JA4 /
		// IP-only / JA4-only) flips by clearing one of the input fields
		// during edit; the manager re-validates uniqueness.
		id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
		if err != nil || id <= 0 {
			redir("invalid id")
			return
		}
		ip := strings.TrimSpace(r.FormValue("ip"))
		ja4 := strings.TrimSpace(r.FormValue("ja4"))
		scope := strings.TrimSpace(r.FormValue("scope"))
		reason := strings.TrimSpace(r.FormValue("reason"))
		durSec, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("duration_sec")), 10, 64)
		action := strings.TrimSpace(r.FormValue("ban_action"))
		if action != "" && !settings.IsValidRateChallengeMode(action) {
			action = ""
		}
		if ip == "" && ja4 == "" {
			redir("ip or ja4 is required")
			return
		}
		if err := h.BanMgr.UpdateManual(r.Context(), id, ip, ja4, scope, reason, action, durSec); err != nil {
			redir("edit: " + err.Error())
			return
		}
		if h.UserRepo != nil {
			h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "ban_edit",
				fmt.Sprintf("%d|%s|%s", id, ip, ja4),
				fmt.Sprintf(`{"reason":%q,"duration_sec":%d,"action":%q}`, reason, durSec, action))
		}
		redir("")
		return

	case "save-defaults":
		// Manual BAN default action editor inlined on /admin/bans/ so the
		// operator can adjust the deny / captcha_only knob from the same
		// page that lists active BANs and exposes the add form.  The
		// shared-bans fallback lives on the "共有 BAN" settings tab now
		// (= /admin/settings/community-bans/) to keep all shared-bans
		// preferences in one place.
		manualAct := strings.TrimSpace(r.FormValue("bans_manual_default_action"))
		cur, err := settings.Load(h.ConfigPath)
		if err != nil {
			redir("load: " + err.Error())
			return
		}
		if manualAct != "" && !settings.IsValidRateChallengeMode(manualAct) {
			manualAct = ""
		}
		cur.Nginx.Bans.ManualDefaultAction = manualAct
		cur.Nginx.SeenVersion = "v" + h.Version
		if err := settings.Save(cur, h.ConfigPath); err != nil {
			redir("save: " + err.Error())
			return
		}
		settingsMu.Lock()
		h.settingsPtr.Store(&cur)
		settingsMu.Unlock()
		if h.UserRepo != nil {
			h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "bans_save_defaults",
				"", fmt.Sprintf(`{"manual":%q}`, manualAct))
		}
		redir("")
		return

	case "subscribe-toggle":
		// Set the community-bans subscribe mode (off / fetch / fetch_apply).
		// terms / submit / URL override etc. live in settings/community-bans/.
		modeVal := strings.TrimSpace(r.FormValue("subscribe_mode"))
		switch modeVal {
		case settings.SubscribeOff, settings.SubscribeFetch, settings.SubscribeFetchApply:
			// valid
		default:
			modeVal = settings.SubscribeOff
		}
		cur, err := settings.Load(h.ConfigPath)
		if err != nil {
			redir("load: " + err.Error())
			return
		}
		cur.CommunityBans.SubscribeMode = modeVal
		cur.Nginx.SeenVersion = "v" + h.Version
		if err := settings.Save(cur, h.ConfigPath); err != nil {
			redir("save: " + err.Error())
			return
		}
		settingsMu.Lock()
		h.settingsPtr.Store(&cur)
		settingsMu.Unlock()

		// To keep the first pull right after turning this ON from hitting "no
		// token", trigger register asynchronously if no token is set yet
		// (= communitybans.Submit has a sync retry too, but get it ahead of time here).
		if modeVal != settings.SubscribeOff && h.CommunityBans != nil && strings.TrimSpace(cur.CommunityBans.Token) == "" {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				if err := h.CommunityBans.Register(ctx); err != nil {
					log.Printf("communitybans: subscribe-toggle register: %v", err)
				}
			}()
		}
		if h.UserRepo != nil {
			h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "subscribe_toggle",
				"", fmt.Sprintf(`{"mode":%q}`, modeVal))
		}
		redir("")
		return

	default:
		redir("unknown op: " + op)
	}
}

// direct-access reference (= suppress the "imported and not used" warning)
var _ = user.RoleAdmin
