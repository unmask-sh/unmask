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
// The honeypot-derived default TTL (= ban_duration) has been moved to settings/?tab=honeypot.
// Detailed community-bans settings (terms / submit / URL override etc.) live in settings/?tab=community-bans.
// The bans page is intentionally a shortcut UX that triggers only **subscribe (= receive)**.
package handlers

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/communitybans"
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
	bansCfg := h.Settings.Nginx.Bans
	honeyDefault := h.Settings.Nginx.Honeypot.DefaultAction
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
		mapDir = "/etc/unmask"
	}
	doc, err := communitybans.ReadDocument(mapDir)
	if err != nil {
		log.Printf("bans: community-bans read doc: %v", err)
		// keep rendering (= treat as empty doc).
	}
	match := strings.TrimSpace(r.URL.Query().Get("match"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	// FeedEntry + CountryCode (= for the flag rendered to the left of the IP popover).
	type feedRow struct {
		communitybans.FeedEntry
		CountryCode string
	}
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
		filtered = append(filtered, feedRow{FeedEntry: e, CountryCode: lookupCC(e.IP)})
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
		s := strings.TrimSpace(br.Entry.Source)
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

	// "Community Bans 効果": past-30d traffic hit count from unmask_event.
	// Honors the dialect-specific JSON-extract syntax (= sqlite vs mariadb)
	// via the same helper the dashboard queries use.  Failures fall through
	// to zero counts so the card still renders even if the DB driver is
	// momentarily unhappy.
	var hitCount, hitUniqueIP int
	if h.DB != nil {
		var jsonExpr string
		if h.DB.Driver == "sqlite" {
			jsonExpr = `json_extract(payload_json, '$.ban_source')`
		} else {
			jsonExpr = `JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.ban_source'))`
		}
		var dateExpr string
		if h.DB.Driver == "sqlite" {
			dateExpr = `date_created >= datetime('now', '-30 days')`
		} else {
			dateExpr = `date_created >= DATE_SUB(NOW(), INTERVAL 30 DAY)`
		}
		row := h.DB.QueryRowContext(r.Context(),
			`SELECT COUNT(*), COUNT(DISTINCT ip_address)
			   FROM unmask_event
			  WHERE phase = 'serve'
			    AND `+jsonExpr+` = 'community_bans'
			    AND `+dateExpr)
		_ = row.Scan(&hitCount, &hitUniqueIP)
	}
	data := map[string]any{
		"Lang":                   i18n.Resolve(r),
		"TZ":                     resolveTZ(r),
		"BasePath":               h.Settings.Server.BasePath,
		"Version":                h.Version,
		"Entries":                banRows,
		"BanFilePath":            h.Settings.Nginx.Honeypot.BanFilePath,
		"Bans":                   h.Settings.Nginx.Bans,
		"Saved":                  r.URL.Query().Get("saved") != "",
		"Error":                  readFlash(w, r, h.Settings.Server.BasePath, "err"),
		"SubscribeEnabled":       cur.CommunityBans.SubscribeEnabled,
		"MyHN":                   myHN,
		"SourcePills":            sourcePills,
		"CommunityBansFromHub":   sourceCounts["community_bans"],
		"CommunityBansHits30d":   hitCount,
		"CommunityBansHitsUniqueIP30d": hitUniqueIP,
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
		mapDir = "/etc/unmask"
	}
	doc, err := communitybans.ReadDocument(mapDir)
	if err != nil {
		log.Printf("community-bans: read doc: %v", err)
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
	}
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
		filtered = append(filtered, feedRow{FeedEntry: e, CountryCode: lookupCC(e.IP)})
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

	data := map[string]any{
		"Lang":                         i18n.Resolve(r),
		"TZ":                           resolveTZ(r),
		"BasePath":                     h.Settings.Server.BasePath,
		"Version":                      h.Version,
		"SubscribeEnabled":             cur.CommunityBans.SubscribeEnabled,
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
		"CommunityBansMatch":           match,
		"CommunityBansQuery":           q,
		"CommunityBansMapDir":          mapDir,
		"Page":                         page,
		"PageNext":                     page + 1,
		"PagePrev":                     page - 1,
		"TotalPages":                   totalPages,
		"PerPage":                      perPage,
		"PageStart":                    start + 1,
		"PageEnd":                      end,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "community_bans.html", data); err != nil {
		log.Printf("community-bans render: %v", err)
	}
}

// AdminCommunityBansDetail: GET /admin/api/community-bans/detail?ip=...&ja4=...
//
// Thin proxy to the hub's public /api/feed/aggregate endpoint.  The hub
// endpoint is open by design (= raw signals are intentionally public so users
// can audit verdicts), but the admin still proxies it so:
//
//	1. the browser only talks to its own admin origin (= avoids a CORS round-trip)
//	2. the operator can point CommunityBans.AggregateURL at a custom hub
//	   without touching the front-end
//	3. local debugging works behind networks that block the public hub
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
	req.Header.Set("User-Agent", "unmask-admin/"+h.Version+" community-bans-detail-proxy")
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
	req.Header.Set("User-Agent", "unmask-admin/"+h.Version+" community-bans-proxy")
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
	base := h.Settings.Server.BasePath
	// return_to lets a form posted from a different page (= the subscribe
	// toggle lives on both /admin/bans/ and /admin/community-bans/) come
	// back to where it was submitted.  Whitelist to known admin sub-paths
	// so the field can't be turned into an open redirect.
	returnTo := base + "/admin/bans/"
	switch strings.TrimSpace(r.FormValue("return_to")) {
	case "community-bans":
		returnTo = base + "/admin/community-bans/"
	case "bans", "":
		returnTo = base + "/admin/bans/"
	}
	redir := func(msg string) {
		dst := returnTo
		if msg == "" {
			dst += "?saved=1"
		} else {
			setFlash(w, base, "err", msg)
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
		if ip == "" {
			redir("ip is required")
			return
		}
		if err := h.BanMgr.AddManual(r.Context(), ip, ja4, reason, meUsername, action, durSec); err != nil {
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

	case "save-defaults":
		// Manual BAN default action editor inlined on /admin/bans/ so the
		// operator can adjust the deny / captcha_only knob from the same
		// page that lists active BANs and exposes the add form.  The
		// shared-bans fallback lives on the "共有 BAN" settings tab now
		// (= /admin/settings/?tab=community-bans) to keep all shared-bans
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
		h.Settings = cur
		settingsMu.Unlock()
		if h.UserRepo != nil {
			h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "bans_save_defaults",
				"", fmt.Sprintf(`{"manual":%q}`, manualAct))
		}
		redir("")
		return

	case "subscribe-toggle":
		// Turn community-bans subscribe (= pull) ON/OFF.  Top-right toggle only.
		// terms / submit / URL override etc. live in settings/?tab=community-bans.
		want := r.FormValue("subscribe_enabled") == "1"
		cur, err := settings.Load(h.ConfigPath)
		if err != nil {
			redir("load: " + err.Error())
			return
		}
		cur.CommunityBans.SubscribeEnabled = want
		cur.Nginx.SeenVersion = "v" + h.Version
		if err := settings.Save(cur, h.ConfigPath); err != nil {
			redir("save: " + err.Error())
			return
		}
		settingsMu.Lock()
		h.Settings = cur
		settingsMu.Unlock()

		// To keep the first pull right after turning this ON from hitting "no
		// token", trigger register asynchronously if no token is set yet
		// (= communitybans.Submit has a sync retry too, but get it ahead of time here).
		if want && h.CommunityBans != nil && strings.TrimSpace(cur.CommunityBans.Token) == "" {
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
				"", fmt.Sprintf(`{"enabled":%t}`, want))
		}
		redir("")
		return

	default:
		redir("unknown op: " + op)
	}
}

// direct-access reference (= suppress the "imported and not used" warning)
var _ = user.RoleAdmin
