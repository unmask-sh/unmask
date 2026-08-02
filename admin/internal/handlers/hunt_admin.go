// bot-hunting tab: page through unmask_event to find bots and act with a single click.
//
// Structure:
//  1. Top N rankings for the last N minutes (= top 30 by IP / JA4 / UA, ordered by req count desc).
//     Each row carries [BAN now] / [UA blacklist] / [JA4 verdict bot] buttons.
//  2. Raw-log pager (= unmask_event in reverse chronological order, 100-1000 / page via ?n=).
//     Filters: exact IP / JA4 substring / phase / time range.
//  3. Live tail (= reuses the existing SSE /admin/api/events/stream from JS in the template).
//
// Action endpoint:
//
//	POST /admin/hunt/action  op=ban|ua_blacklist|ja4_bot
package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// staticAssetsTipPatterns are compiled from the static-assets bypass-path
// preset in nginxconf.BypassPathPresetGroups -- the same regex set that the
// rendered nginx map uses.  Reusing the preset keeps the hunt-page tip and
// the actual bypass behaviour in sync; if the preset gains a new pattern
// (e.g. another well-known asset path), the tip starts counting it too.
var (
	staticAssetsTipPatternsOnce sync.Once
	staticAssetsTipPatterns     []*regexp.Regexp
)

func compileStaticAssetsTipPatterns() []*regexp.Regexp {
	staticAssetsTipPatternsOnce.Do(func() {
		for _, g := range nginxconf.BypassPathPresetGroups {
			if g.ID != "static-assets" {
				continue
			}
			for _, r := range g.Rules {
				if re, err := regexp.Compile(r.Pattern); err == nil {
					staticAssetsTipPatterns = append(staticAssetsTipPatterns, re)
				}
			}
		}
	})
	return staticAssetsTipPatterns
}

// huntTipDismissedCookie carries a comma-separated list of tip IDs the
// operator has dismissed.  Written by hunt.html's dismiss button, read here
// so the banner does not re-appear after the page reload.
const huntTipDismissedCookie = "unmask_hunt_tip_dismissed"

func isHuntTipDismissed(r *http.Request, tipID string) bool {
	c, err := r.Cookie(huntTipDismissedCookie)
	if err != nil || c == nil {
		return false
	}
	v := decodeCookieValue(c.Value)
	for _, id := range strings.Split(v, ",") {
		if strings.TrimSpace(id) == tipID {
			return true
		}
	}
	return false
}

// bypassPathsPresetEnabled reports whether the given preset ID appears in
// the operator's BypassPathsConfig.EnabledPresets list.  Inline scan; the
// list is tiny (= a handful of preset IDs).
func bypassPathsPresetEnabled(b settings.BypassPathsConfig, id string) bool {
	for _, p := range b.EnabledPresets {
		if p == id {
			return true
		}
	}
	return false
}

// refFromQuery pulls the 16-hex support correlation id out of the hunt search
// box.  The operator normally pastes just the id (it double-click-selects), but
// tolerate a "Ref ID: <id>" paste by returning the first run of 16 hex chars.
// "" (no run found) disables the filter.  Hex-only by construction, so the
// FetchPaged LIKE pattern it feeds stays free of SQL/LIKE metacharacters.
func refFromQuery(s string) string {
	s = strings.ToLower(s)
	run, start := 0, -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			if run == 0 {
				start = i
			}
			run++
			if run == 16 {
				return s[start : start+16]
			}
		} else {
			run = 0
		}
	}
	return ""
}

// AdminHuntIndex: GET /admin/hunt/ — ranking + raw log + live tail.
func (h *Handler) AdminHuntIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	rng := q.Get("range")
	var sinceMin int
	switch rng {
	case "1h", "":
		rng = "1h"
		sinceMin = 60
	case "6h":
		sinceMin = 360
	case "24h":
		sinceMin = 1440
	case "custom":
		sinceMin = 1440 // fallback span until valid dates are picked
	default:
		rng = "1h"
		sinceMin = 60
	}
	// custom range: from/to are operator-TZ calendar dates resolved to a UTC
	// window threaded through huntCtx; the event queries then bound to it instead
	// of the trailing sinceMin.  An invalid range keeps rng="custom" (so the
	// picker stays visible) but leaves the window unset, so sinceMin applies until
	// valid dates are entered.
	huntCtx := r.Context()
	var customFromTS, customToTS int64
	customValid := false
	if rng == "custom" {
		customFromTS, customToTS = parseCustomRange(q.Get("from"), q.Get("to"), resolveLocation(r))
		customValid = customFromTS > 0 && customToTS > customFromTS
		if customValid {
			huntCtx = events.WithHuntWindow(huntCtx, customFromTS, customToTS)
		}
	}

	ipFilter := strings.TrimSpace(q.Get("ip"))
	ja4Filter := strings.TrimSpace(q.Get("ja4"))
	// ua: substring over the stored User-Agent.  Length-capped to the column
	// width so a pathological paste can't blow up the LIKE; the value rides a ?
	// placeholder in FetchPaged, so trimming is all the sanitation it needs.
	uaFilter := strings.TrimSpace(q.Get("ua"))
	if len(uaFilter) > 255 {
		uaFilter = uaFilter[:255]
	}
	// ref: the support correlation id a blocked visitor quotes.  refFromQuery
	// pulls the 16-hex id out (tolerating a "Ref ID: <id>" paste) so the search
	// resolves the exact serve event.
	refFilter := refFromQuery(q.Get("ref"))
	phaseFilter := strings.TrimSpace(q.Get("phase"))
	forceReasonFilter := strings.TrimSpace(q.Get("force_reason"))
	// asn: drill down from the network ranking into the requests behind a row.
	// The event carries no ASN column, so this resolves the window's addresses
	// and filters on the ones that belong to the network -- the same scan the
	// ranking itself does, on a page the operator asked for explicitly.
	asnFilter := 0
	asnIPs, asnIPTotal := 0, 0
	asnOrg := ""
	if v := strings.TrimSpace(q.Get("asn")); v != "" {
		if n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimPrefix(v, "AS"), "as")); err == nil && n > 0 {
			asnFilter = n
		}
	}
	// The filter takes a comma-separated list so the UI can offer groups
	// ("everything that passed"), so validate it as a list and keep the
	// canonical form -- validating it as one name silently dropped every
	// group back to "no filter", which reads as the filter having been
	// ignored.  An entirely unknown value is preserved rather than blanked:
	// FetchPaged then returns nothing, which is what a filter nobody
	// recognises should do, instead of quietly showing the whole log.
	if canon := events.CanonicalPhaseFilter(phaseFilter); canon != "" {
		phaseFilter = canon
	}
	// Which rank cards the operator has folded away.  Resolved server-side, not
	// in JS, so the row does not render at full width and then jump -- the same
	// reason the host / site pickers read their cookies here.
	rankFolded := resolveRankFolded(r)
	// Whether the UA card shows the raw string instead of the summary.  Folding
	// a card can hand the UA column enough width to read one, and an operator
	// chasing a spoofed UA wants the whole thing, not "Windows 10+ · Chrome 142".
	rankUAFull := cookieIsSet(r, "unmask_rank_ua_full")
	// host filter (= global scope of the shared host_picker.  comes from
	// the unmask_hosts cookie / ?host=).
	hostFilters := resolveHostFilter(r)
	// site filter (= global scope of the shared site_picker.  single-select,
	// from the unmask_site cookie / ?site=).
	siteFilter := resolveSiteFilter(r)
	offset := 0
	if s := q.Get("offset"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			offset = n
		}
	}

	// Freeze the result set the moment the operator leaves page 1, and carry
	// that id in the pager links (see events.WithHuntFreeze -- without it,
	// arriving events push already-read rows down into the next page).  Page 1
	// with no id stays live, so a plain reload shows the newest events and
	// starts a fresh freeze from there.
	freezeID := int64(0)
	if s := q.Get("asof"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			freezeID = n
		}
	}
	if freezeID == 0 {
		if id, err := events.MaxEventID(huntCtx, h.DB); err != nil {
			log.Printf("hunt freeze point: %v", err) // paging stays live; rows may repeat
		} else {
			freezeID = id
		}
	}
	if freezeID > 0 {
		huntCtx = events.WithHuntFreeze(huntCtx, freezeID)
	}

	// Rows per page.  Whitelisted so ?n= can't turn into an unbounded query;
	// operators hunting a burst want more than the classic 100 on screen.
	pageSize := 100
	switch q.Get("n") {
	case "200":
		pageSize = 200
	case "500":
		pageSize = 500
	case "1000":
		pageSize = 1000
	}
	if asnFilter > 0 && h.IPGeo != nil && h.IPGeo.ASNLoaded() {
		ips, total, org, err := events.IPsInASN(huntCtx, h.DB, sinceMin, uint(asnFilter), h.IPGeo.LookupASN)
		if err != nil {
			log.Printf("hunt asn drill-down: %v", err)
		}
		asnIPs, asnIPTotal, asnOrg = len(ips), total, org
		huntCtx = events.WithIPSet(huntCtx, ips)
	} else if asnFilter > 0 {
		// Asked for a network on an install that cannot resolve one.  Show
		// nothing rather than the unfiltered log, which would read as the
		// network accounting for every request on the page.
		huntCtx = events.WithIPSet(huntCtx, nil)
	}
	rows, windowStart, err := events.FetchPagedWithBleed(huntCtx, h.DB, ipFilter, ja4Filter, uaFilter, refFilter, phaseFilter, forceReasonFilter, siteFilter, hostFilters, sinceMin, pageSize, offset)
	if err != nil {
		log.Printf("hunt fetch: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	rows, hasMoreRows := ownedSessionRows(rows, windowStart, pageSize)

	// Hosts / HostSelected / SelfHostID (= for the shared host_picker) are
	// injected by addMeToData, which is shared by every admin page.

	// Three ranking tables (= filters are not applied.  Top entries within
	// the tab's sinceMin window).
	ipRankRaw, _ := events.RankByIP(huntCtx, h.DB, sinceMin, 30)
	ja4RankRaw, _ := events.RankByJA4(huntCtx, h.DB, sinceMin, 30)
	uaRankRaw, _ := events.RankByUA(huntCtx, h.DB, sinceMin, 30)

	cur := h.snapshotSettings().Nginx

	// IP ranking: badge if already in the BAN list, BAN button otherwise.
	type ipRankRow struct {
		Key         string
		Count       int
		Banned      bool   // true if an existing entry in unmask_ban
		BypassIP    bool   // true if in the bypass_ips list (= rescued, BAN unnecessary)
		CountryCode string // ISO 3166-1 alpha-2 (= IP-geo lookup. empty if mmdb is not loaded)
	}
	ipRank := make([]ipRankRow, 0, len(ipRankRaw))
	bypassSet := map[string]bool{}
	for _, ip := range cur.BypassIPs {
		bypassSet[strings.TrimSpace(ip)] = true
	}
	for _, r0 := range ipRankRaw {
		row := ipRankRow{Key: r0.Key, Count: r0.Count}
		if r0.Key != "" && h.BanMgr != nil {
			row.Banned = h.BanMgr.IsBanned(r.Context(), r0.Key, "")
		}
		if bypassSet[r0.Key] {
			row.BypassIP = true
		}
		if h.IPGeo != nil && h.IPGeo.Loaded() && r0.Key != "" {
			row.CountryCode = h.IPGeo.LookupInfo(r0.Key).Country
		}
		ipRank = append(ipRank, row)
	}

	// JA4 ranking: run the existing verdict resolution (= preset / extra).
	type ja4RankRow struct {
		Key     string
		Count   int
		Verdict string // verdict name if already registered, "" otherwise (= show button)
		Action  string // "bot" / "suspect" / "ok"
		Source  string // "preset:<id>" or "extra"
	}
	ja4Rank := make([]ja4RankRow, 0, len(ja4RankRaw))
	for _, r0 := range ja4RankRaw {
		row := ja4RankRow{Key: r0.Key, Count: r0.Count}
		if r0.Key != "" {
			if v, a, src := lookupJA4Verdict(r0.Key, cur); v != "" {
				row.Verdict, row.Action, row.Source = v, a, src
			}
		}
		ja4Rank = append(ja4Rank, row)
	}

	// UA ranking: decide whether the UA hits an already-registered list
	// (= challenge_targets / search_bots).
	type uaRankRow struct {
		Key      string
		Count    int
		Listed   string // already-registered group / "extra" name, "" if unregistered
		Category string // "challenge" (= blocked) / "search_ai" (= rescued) / "" (= unregistered)
	}
	uaRank := make([]uaRankRow, 0, len(uaRankRaw))
	for _, r0 := range uaRankRaw {
		row := uaRankRow{Key: r0.Key, Count: r0.Count}
		if r0.Key != "" {
			row.Listed, row.Category = lookupUAListed(r0.Key, cur)
		}
		uaRank = append(uaRank, row)
	}

	// ASN ranking: which NETWORKS the window came from, ordered by how many
	// distinct addresses each contributed.  This is the view the IP ranking
	// cannot give -- a botnet renting a few thousand addresses inside one
	// hosting AS puts every single one of them near the bottom of a
	// by-request ranking, while the network it rents from is the one thing
	// all of them share and the only handle wide enough to act on.
	type asnRankRow struct {
		ASN   uint
		Org   string
		IPs   int
		Count int
		Rule  string // action of the ASN rule already covering it, "" if none
	}
	var asnRank []asnRankRow
	if h.IPGeo != nil && h.IPGeo.ASNLoaded() {
		// LookupASN, not LookupInfo: this walks every distinct IP in the window
		// once, where LookupInfo's country lookup is wasted work and its cache
		// is pure overhead (see ipgeo.LookupASN).
		asnRaw, _ := events.RankByASN(huntCtx, h.DB, sinceMin, 20, h.IPGeo.LookupASN)
		asnRank = make([]asnRankRow, 0, len(asnRaw))
		for _, r0 := range asnRaw {
			asnRank = append(asnRank, asnRankRow{
				ASN: r0.ASN, Org: r0.Org, IPs: r0.IPs, Count: r0.Count,
				Rule: lookupASNRuleAction(r0.ASN, r0.Org, cur.Asn),
			})
		}
	}

	// Row count is no longer the signal: rows now includes whatever spilled in
	// from the neighbouring pages to finish a session, so it can exceed
	// pageSize on a full page and fall short on the last one.
	hasMore := hasMoreRows

	// Attach country code + ban status to event rows.  The same IP appears
	// on multiple rows, so cache per IP (= avoid duplicate lookups).
	//   - CountryCode: empty when IP-geo is not loaded
	//   - Banned     : an active ban exists for this IP (= including full
	//                  wildcard).  Same semantics as IPRank
	//                  (= ja4 empty when calling IsBanned -> per-IP count).
	// huntBanInfo: the ban-list record behind an "already BANned" row, surfaced
	// in a popover so the operator sees WHY the IP is banned without leaving the
	// hunt log.  Source/Reason answer "what tripped it"; Action is the effective
	// enforcement; When/By/Expires give provenance.  Times are pre-formatted in
	// the operator's TZ (same cookie the rest of the page uses).
	type huntBanInfo struct {
		Source  string
		Reason  string
		Action  string
		When    string
		By      string
		Expires string // "" = permanent
	}
	banTZ := resolveLocation(r)
	type huntEventRow struct {
		events.Row
		CountryCode string
		Banned      bool
		Ban         *huntBanInfo // nil unless this IP has a ban record with detail
	}
	enriched := make([]huntEventRow, 0, len(rows))
	geoOK := h.IPGeo != nil && h.IPGeo.Loaded()
	banOK := h.BanMgr != nil
	ipCC := map[string]string{}
	ipBan := map[string]bool{}
	// banByIP: IP -> its ban record, for the popover detail.  One Snapshot read
	// (not a lookup per row); only IP-bearing entries (ip_only / ip_ja4) key in,
	// which is exactly what the per-IP IsBanned pill reflects.
	banByIP := map[string]ban.Entry{}
	if banOK {
		for _, e := range h.BanMgr.Snapshot() {
			if e.IP == "" {
				continue
			}
			if _, dup := banByIP[e.IP]; !dup {
				banByIP[e.IP] = e
			}
		}
	}
	for _, e := range rows {
		if e.IP == "" {
			continue
		}
		if geoOK {
			if _, ok := ipCC[e.IP]; !ok {
				ipCC[e.IP] = h.IPGeo.LookupInfo(e.IP).Country
			}
		}
		if banOK {
			if _, ok := ipBan[e.IP]; !ok {
				ipBan[e.IP] = h.BanMgr.IsBanned(r.Context(), e.IP, "")
			}
		}
	}
	for _, e := range rows {
		row := huntEventRow{
			Row:         e,
			CountryCode: ipCC[e.IP],
			Banned:      ipBan[e.IP],
		}
		if row.Banned {
			if be, ok := banByIP[e.IP]; ok {
				expires := ""
				if !be.ExpiresAt.IsZero() {
					expires = be.ExpiresAt.In(banTZ).Format("2006-01-02 15:04")
				}
				row.Ban = &huntBanInfo{
					Source:  be.Source,
					Reason:  be.Reason,
					Action:  h.BanMgr.EffectiveAction(be.Action, be.Source),
					When:    be.BannedAt.In(banTZ).Format("2006-01-02 15:04"),
					By:      be.BannedBy,
					Expires: expires,
				}
			}
		}
		enriched = append(enriched, row)
	}

	// Static-assets tip: when many hunt rows hit paths the static-assets
	// bypass preset would cover (= /static/, /assets/, /favicon.ico etc.),
	// suggest enabling the preset.  Skipped when the preset is already on
	// or the operator dismissed the tip in this browser.  Threshold of 20
	// matches the "many rows" intent without firing on the occasional
	// /robots.txt hit in a quiet hour.
	staticAssetsTipHits := 0
	showStaticAssetsTip := false
	if !bypassPathsPresetEnabled(cur.BypassPaths, "static-assets") &&
		!isHuntTipDismissed(r, "static-assets") {
		pats := compileStaticAssetsTipPatterns()
		for _, e := range enriched {
			p := e.Path
			if p == "" {
				continue
			}
			if i := strings.IndexByte(p, '?'); i >= 0 {
				p = p[:i]
			}
			for _, re := range pats {
				if re.MatchString(p) {
					staticAssetsTipHits++
					break
				}
			}
		}
		if staticAssetsTipHits >= 20 {
			showStaticAssetsTip = true
		}
	}

	// Custom-range calendar: pre-fill the date inputs with the current window and
	// bound them to [oldest event, today] in the operator TZ.
	loc := resolveLocation(r)
	oldestTS, _ := dashboard.OldestEventTS(huntCtx, h.DB)
	dataMinDate := ""
	if oldestTS > 0 {
		dataMinDate = time.Unix(oldestTS, 0).In(loc).Format("2006-01-02")
	}
	nowT := time.Now()
	dataMaxDate := nowT.In(loc).Format("2006-01-02")
	customFrom := strings.TrimSpace(q.Get("from"))
	if customFrom == "" {
		if customValid {
			customFrom = time.Unix(customFromTS, 0).In(loc).Format("2006-01-02")
		} else {
			customFrom = nowT.Add(-time.Duration(sinceMin) * time.Minute).In(loc).Format("2006-01-02")
		}
	}
	customTo := strings.TrimSpace(q.Get("to"))
	if customTo == "" {
		customTo = nowT.In(loc).Format("2006-01-02")
	}

	// visibleSessions: what the session-collapse JS will leave on screen --
	// one line per beacon token plus every token-less row.  Feeds the pager
	// caption so "100 rows" and "20 visible lines" stop contradicting.
	visibleSessions := 0
	seenTok := map[string]bool{}
	for i := range enriched {
		tok := enriched[i].BeaconToken
		if tok == "" {
			visibleSessions++
			continue
		}
		if !seenTok[tok] {
			seenTok[tok] = true
			visibleSessions++
		}
	}
	rowUAList := make([]string, len(enriched))
	for i := range enriched {
		rowUAList[i] = enriched[i].UA
	}
	// The network card only renders when the ASN database can name networks.
	renderedCards := []string{"ip", "ja4", "ua"}
	if len(asnRank) > 0 {
		renderedCards = append(renderedCards, "asn")
	}
	rankFolded = dropFoldIfAllFolded(rankFolded, renderedCards)
	data := map[string]any{
		"Lang":        i18n.Resolve(r),
		"TZ":          resolveTZ(r),
		"CustomFrom":  customFrom,
		"CustomTo":    customTo,
		"DataMinDate": dataMinDate,
		"DataMaxDate": dataMaxDate,
		"BasePath":    h.cfg().Server.BasePath,
		"Version":     h.Version,
		"Range":       rng,
		"SinceMin":    sinceMin,
		"IPFilter":    ipFilter,
		"JA4Filter":   ja4Filter,
		"UAFilter":    uaFilter,
		"RefFilter":   refFilter,
		"Phase":       phaseFilter,
		"ForceReason": forceReasonFilter,
		// Filtering hides the IP/JA4/UA rankings on page 1 when a value
		// filter is active (host scope alone doesn't count -- rankings stay
		// useful when narrowed to one host). The raw-log table still shows.
		"RankFolded":    rankFolded,
		"RankUAFull":    rankUAFull,
		"ASNFilter":     asnFilter,
		"ASNFilterIPs":  asnIPs,
		"ASNFilterOrg":  asnOrg,
		"ASNFilterMore": asnIPTotal > asnIPs,
		"Filtering":     ipFilter != "" || ja4Filter != "" || uaFilter != "" || refFilter != "" || phaseFilter != "" || asnFilter > 0,
		// UABotNote: per listed-crawler UA, which reading its badge note
		// carries (address check failed / configured target / generic).
		"UABotNote":  uaBotNoteByUA(rowUAList, cur),
		"Rows":       enriched,
		"IPRank":     ipRank,
		"JA4Rank":    ja4Rank,
		"UARank":     uaRank,
		"ASNRank":    asnRank,
		"Offset":     offset,
		"PageSize":   pageSize,
		"NextOffset": offset + pageSize,
		"PrevOffset": maxInt(offset-pageSize, 0),
		"HasMore":    hasMore,
		"HasPrev":    offset > 0,
		// Range caption fits the seek pager's right-hand info slot.  We don't
		// expose a total (= unmask_event would need a window-scoped COUNT(*)
		// that doesn't scale), but "N-M 件目を表示中" is cheap and useful.
		"PagerSeek": buildHuntPagerSeek(
			i18n.Resolve(r), rng, ipFilter, ja4Filter, uaFilter, phaseFilter, q,
			offset, pageSize, offset > 0, hasMore,
			huntRangeText(i18n.Resolve(r), offset, len(enriched), visibleSessions),
			freezeID,
		),
		"Saved": q.Get("saved") != "",
		"Error": readFlash(w, r, h.cfg().Server.BasePath, "err"),
		// Static-assets tip: rendered as a dismissible banner above the
		// range bar when paths matching the static-assets preset show up
		// ≥ 20 times in the current page.
		"ShowStaticAssetsTip": showStaticAssetsTip,
		"StaticAssetsTipHits": staticAssetsTipHits,
		"StaticAssetsTipHref": h.cfg().Server.BasePath + "/admin/settings/?tab=bypass-paths",
		// Hosts / HostSelected / SelfHostID are injected commonly by addMeToData.
		// CommunityBansActive: whether to show the shared row in the BAN
		// confirmation dialog.  true only when submit_enabled=true AND the
		// terms have been accepted.  false -> the dialog is a plain confirm.
		"CommunityBansActive": h.snapshotSettings().CommunityBans.SubmitActive(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "hunt.html", data); err != nil {
		log.Printf("hunt render: %v", err)
	}
}

// rangeToMinutes mirrors the range parsing in AdminHunt so the action
// handler can resolve the same sample window the ranking aggregated over.
// Unknown / empty -> 60 minutes (= the "1h" default).
// lookupASNRuleAction reports the action of the ASN-tab rule already covering a
// network, or "" when none does.  It answers the only question the ranking has
// to answer before the operator acts: "have I already dealt with this one?"
//
// Both rule shapes are checked the way the ASN axis itself resolves them -- an
// exact AS number, and an organization-name substring (which is also how the
// built-in hosting-provider presets match, so an enabled "Amazon" preset shows
// up here for every Amazon AS).  Rate-mode rules are reported too: throttled is
// not untouched, and showing such a row as unhandled would invite a second,
// conflicting rule.
func lookupASNRuleAction(asn uint, org string, cfg settings.AsnConfig) string {
	if asn != 0 {
		for _, r := range cfg.EnabledASNRules() {
			if r.ASN == asn {
				return r.Action
			}
		}
	}
	if org != "" {
		lower := strings.ToLower(org)
		for _, p := range cfg.EnabledOrgPatterns() {
			if pat := strings.ToLower(strings.TrimSpace(p.Pattern)); pat != "" && strings.Contains(lower, pat) {
				return p.Action
			}
		}
	}
	// Rate-mode rules live in a separate list (they render as a throttle zone,
	// not an immediate action), so they need their own pass.
	for _, r := range cfg.RateRules() {
		if r.ASN != 0 && r.ASN == asn {
			return r.Action
		}
		if r.Org != "" && org != "" && strings.Contains(strings.ToLower(org), strings.ToLower(r.Org)) {
			return r.Action
		}
	}
	return ""
}

func rangeToMinutes(rng string) int {
	switch strings.TrimSpace(rng) {
	case "6h":
		return 360
	case "24h":
		return 1440
	default:
		return 60
	}
}

// AdminHuntAction: POST /admin/hunt/action — dispatch on op:
//
//	op=ban           : add ip + ja4 to the persistent BAN list
//	                   (= source=manual / reason="bot hunt")
//	op=ua_blacklist  : add a UA pattern to ChallengeTargets.Extra
//	op=ja4_bot       : add a JA4 pattern to JA4Verdicts.Extra (= action=bot)
func (h *Handler) AdminHuntAction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	base := h.cfg().Server.BasePath
	redir := func(msg string) {
		dst := base + "/admin/hunt/?range=" + url.QueryEscape(r.FormValue("range"))
		if msg == "" {
			dst += "&saved=1"
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
	if h.UserRepo != nil {
		if me, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			meUsername = me.Username
		}
	}

	op := r.FormValue("op")
	switch op {
	case "ban":
		ip := strings.TrimSpace(r.FormValue("ip"))
		ja4 := strings.TrimSpace(r.FormValue("ja4"))
		durSec, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("duration_sec")), 10, 64)
		if ip == "" && ja4 == "" {
			redir("ip or ja4 is required")
			return
		}
		if h.BanMgr == nil {
			redir("ban manager not configured")
			return
		}
		// reason is operator-editable in the BAN dialog.  The local BAN always
		// needs a reason, so fall back to the auto default when empty; the
		// shared (hub) reason, however, is sent verbatim -- empty included (=
		// the operator chose to share without a reason).
		rawReason := strings.TrimSpace(r.FormValue("reason"))
		banReason := rawReason
		if banReason == "" {
			banReason = "bot hunt"
		}
		// Scope comes from the form (= JA4 ranking sets ja4_only).  Empty
		// falls back to DeriveScope.
		scope := strings.TrimSpace(r.FormValue("scope"))
		if err := h.BanMgr.AddManualWithScope(r.Context(), ip, ja4, scope, banReason, meUsername, "", durSec); err != nil {
			redir("ban: " + err.Error())
			return
		}
		if h.UserRepo != nil {
			h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "hunt_ban",
				fmt.Sprintf("%s|%s", ip, ja4),
				fmt.Sprintf(`{"reason":%q,"duration_sec":%d}`, banReason, durSec))
		}
		// submit to community bans (= async if the share checkbox is ON and a
		// CommunityBans client exists).  If the submit fails, the BAN itself
		// still succeeds.
		if h.CommunityBans != nil && strings.TrimSpace(r.FormValue("share")) == "1" {
			comment := r.FormValue("comment")
			// accept_terms=1: case where the user accepted the terms and shared
			// from inside the dialog while previously opted out.  Flip
			// settings.CommunityBans's SubmitEnabled + TermsAcceptedAt here so
			// that subsequent shares are enabled (= the user can revoke from
			// the settings tab).
			if strings.TrimSpace(r.FormValue("accept_terms")) == "1" {
				if cur, err := settings.Load(h.ConfigPath); err == nil {
					if !cur.CommunityBans.SubmitActive() {
						cur.CommunityBans.SubmitEnabled = true
						if cur.CommunityBans.TermsAcceptedAt == 0 {
							cur.CommunityBans.TermsAcceptedAt = time.Now().Unix()
						}
						// Stamp the version so SubmitActive()'s version gate is
						// satisfied (= same as the settings-tab clickwrap path).
						cur.CommunityBans.TermsAcceptedVersion = settings.CurrentCommunityBansTermsVersion
						cur.Nginx.SeenVersion = "v" + h.Version
						if err := settings.Save(cur, h.ConfigPath); err != nil {
							log.Printf("communitybans: accept_terms save: %v", err)
						} else {
							settingsMu.Lock()
							h.settingsPtr.Store(&cur)
							settingsMu.Unlock()
							if h.UserRepo != nil {
								h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "community_bans_accept_terms",
									"", `{"from":"hunt_ban_dialog"}`)
							}
						}
					}
				} else {
					log.Printf("communitybans: accept_terms load: %v", err)
				}
			}
			go func(ip, ja4, reason, comment string) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := h.CommunityBans.Submit(ctx, communitybans.SubmitRequest{
					IP: ip, JA4: ja4, Reason: reason, Comment: comment,
					BanSource: ban.SourceManual,
				}); err != nil {
					log.Printf("communitybans: submit ban %s|%s: %v", ip, ja4, err)
				}
			}(ip, ja4, rawReason, comment)
		}
		redir("")
		return

	case "ua_blacklist":
		pat := strings.TrimSpace(r.FormValue("pattern"))
		title := strings.TrimSpace(r.FormValue("title"))
		if pat == "" {
			redir("pattern is required")
			return
		}
		if err := h.appendUABlacklist(r, pat, title, meUsername, pay.UserID); err != nil {
			redir("ua_blacklist: " + err.Error())
			return
		}
		redir("")
		return

	case "ja4_bot":
		pat := strings.TrimSpace(r.FormValue("pattern"))
		title := strings.TrimSpace(r.FormValue("title"))
		if pat == "" {
			redir("pattern is required")
			return
		}
		if err := h.appendJA4Bot(r, pat, title, meUsername, pay.UserID); err != nil {
			redir("ja4_bot: " + err.Error())
			return
		}
		// Optional community share: when share=1, POST (sample IP, JA4) to
		// the shared feed with BanSource=ja4_ranking so the hub's judge can
		// upgrade the entry to ja4_only (= operator endorsed the fingerprint,
		// not the specific IP).  The user only picked a JA4 in the ranking;
		// admin resolves a representative IP for the same window internally
		// so the hub still receives an (ip, ja4) pair (= ja4-only submit is
		// supported too, but a pair gives richer signal to other consumers).
		// Submit failures don't roll back the local JA4Verdicts.Extra append.
		if h.CommunityBans != nil && strings.TrimSpace(r.FormValue("share")) == "1" {
			ja4 := pat // ja4_bot's pattern IS the JA4 fingerprint
			rawReason := strings.TrimSpace(r.FormValue("reason"))
			comment := r.FormValue("comment")
			// Resolve a representative IP for this JA4 within the same window
			// the ranking aggregated over.  Best-effort: empty when no IP was
			// observed.  hub validation now accepts (ja4) without (ip).
			sampleIP, _ := events.SampleIPForJA4(r.Context(), h.DB, rangeToMinutes(r.FormValue("range")), ja4)
			// accept_terms=1: mirror the op=ban path so opting in via the JA4
			// ranking dialog also activates community submit for future BANs.
			if strings.TrimSpace(r.FormValue("accept_terms")) == "1" {
				if cur, err := settings.Load(h.ConfigPath); err == nil {
					if !cur.CommunityBans.SubmitActive() {
						cur.CommunityBans.SubmitEnabled = true
						if cur.CommunityBans.TermsAcceptedAt == 0 {
							cur.CommunityBans.TermsAcceptedAt = time.Now().Unix()
						}
						cur.CommunityBans.TermsAcceptedVersion = settings.CurrentCommunityBansTermsVersion
						cur.Nginx.SeenVersion = "v" + h.Version
						if err := settings.Save(cur, h.ConfigPath); err != nil {
							log.Printf("communitybans: accept_terms save: %v", err)
						} else {
							settingsMu.Lock()
							h.settingsPtr.Store(&cur)
							settingsMu.Unlock()
							if h.UserRepo != nil {
								h.UserRepo.Record(r.Context(), pay.UserID, meUsername, "community_bans_accept_terms",
									"", `{"from":"hunt_ja4_ranking_dialog"}`)
							}
						}
					}
				} else {
					log.Printf("communitybans: accept_terms load: %v", err)
				}
			}
			go func(ip, ja4, reason, comment string) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := h.CommunityBans.Submit(ctx, communitybans.SubmitRequest{
					IP: ip, JA4: ja4, Reason: reason, Comment: comment,
					BanSource: ban.SourceJA4Ranking,
				}); err != nil {
					log.Printf("communitybans: submit ja4_ranking %s|%s: %v", ip, ja4, err)
				}
			}(sampleIP, ja4, rawReason, comment)
		}
		redir("")
		return

	default:
		redir("unknown op: " + op)
	}
}

// appendUABlacklist: append a new entry to ChallengeTargets.Extra.  Load
// the existing settings.yml -> append -> save -> render.
func (h *Handler) appendUABlacklist(r *http.Request, pattern, title, username string, userID int64) error {
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		return err
	}
	t := strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(title)
	cur.Nginx.ChallengeTargets.Extra = append(cur.Nginx.ChallengeTargets.Extra, pattern)
	cur.Nginx.ChallengeTargets.ExtraTitle = append(cur.Nginx.ChallengeTargets.ExtraTitle, t)
	cur.Nginx.ChallengeTargets.ExtraDisabled = append(cur.Nginx.ChallengeTargets.ExtraDisabled, false)
	cur.Nginx.ChallengeTargets.ExtraUpdatedAt = append(cur.Nginx.ChallengeTargets.ExtraUpdatedAt, nowUnix())
	cur.Nginx.SeenVersion = "v" + h.Version
	if err := settings.Save(cur, h.ConfigPath); err != nil {
		return err
	}
	if err := nginxconf.Render(cur, "", h.Version); err != nil {
		return err
	}
	settingsMu.Lock()
	h.settingsPtr.Store(&cur)
	settingsMu.Unlock()
	if h.UserRepo != nil {
		h.UserRepo.Record(r.Context(), userID, username, "hunt_ua_blacklist",
			pattern, fmt.Sprintf(`{"title":%q}`, t))
	}
	return nil
}

// appendJA4Bot: add to JA4Verdicts.Extra with action=bot.
func (h *Handler) appendJA4Bot(r *http.Request, pattern, title, username string, userID int64) error {
	// Validate the pattern before it is rendered into the (root-loaded) nginx
	// map -- the settings-tab form does this, and this hunt path must not be a
	// weaker bypass.  Reject quote/backslash/control chars (config injection)
	// and an invalid regex (nginx -t failure).  render.go re-checks as a
	// backstop, but reject at the source for a clear error + no silent drop.
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || strings.ContainsAny(pattern, "\"\\\x00\r\n") {
		return fmt.Errorf("invalid JA4 pattern")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("invalid JA4 pattern regex: %w", err)
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		return err
	}
	t := strings.NewReplacer("\n", " ", "\r", " ", "\"", "'", "\\", "/").Replace(title)
	verdict := "hunt_" + strings.ReplaceAll(strings.ReplaceAll(pattern, "_", ""), "[", "")
	if len(verdict) > 40 {
		verdict = verdict[:40]
	}
	cur.Nginx.JA4Verdicts.Extra = append(cur.Nginx.JA4Verdicts.Extra,
		settings.JA4VerdictExtraRule{Pattern: pattern, Verdict: verdict, Action: nginxconf.JA4ActionBot})
	cur.Nginx.JA4Verdicts.ExtraTitle = append(cur.Nginx.JA4Verdicts.ExtraTitle, t)
	cur.Nginx.JA4Verdicts.ExtraDisabled = append(cur.Nginx.JA4Verdicts.ExtraDisabled, false)
	cur.Nginx.JA4Verdicts.ExtraUpdatedAt = append(cur.Nginx.JA4Verdicts.ExtraUpdatedAt, nowUnix())
	settings.BackfillExtraVerdictIDs(&cur) // ID-0 entries were just appended, so assign them now.
	cur.Nginx.SeenVersion = "v" + h.Version
	if err := settings.Save(cur, h.ConfigPath); err != nil {
		return err
	}
	if err := nginxconf.Render(cur, "", h.Version); err != nil {
		return err
	}
	settingsMu.Lock()
	h.settingsPtr.Store(&cur)
	settingsMu.Unlock()
	if h.UserRepo != nil {
		h.UserRepo.Record(r.Context(), userID, username, "hunt_ja4_bot",
			pattern, fmt.Sprintf(`{"title":%q,"verdict":%q}`, t, verdict))
	}
	return nil
}

// nowUnix: standalone helper (= a thin wrapper around time.Now().Unix() so
// tests don't need to stub it).
func nowUnix() int64 {
	return time.Now().Unix()
}

// huntRangeText builds the "N-M 件目 (S セッション) を表示中" caption shown
// next to the seek pager.  The session count is what the operator actually
// SEES: the client-side collapse folds a session's rows into one visible row,
// so a 100-row page can render as ~20 lines -- captioning only "100 件" reads
// as a bug ("where are my 100 rows?").  sessions <= 0 falls back to the plain
// row-range caption (overview and older callers).
func huntRangeText(lang i18n.Lang, offset, gotRows, sessions int) string {
	if gotRows <= 0 {
		return ""
	}
	if sessions > 0 {
		return i18n.Tf(lang, "pager.range_caption_sessions", offset+1, offset+gotRows, sessions)
	}
	return i18n.Tf(lang, "pager.range_caption", offset+1, offset+gotRows)
}

// buildHuntPagerSeek builds a PagerSeekData for the hunt page.  The base
// query carries range / ip / ja4 / phase plus any host=... selections so
// pager links keep the operator's filters intact.
func buildHuntPagerSeek(lang i18n.Lang, rng, ipFilter, ja4Filter, uaFilter, phase string, q url.Values, offset, pageSize int, hasPrev, hasNext bool, rangeText string, freezeID int64) PagerSeekData {
	var sb strings.Builder
	sb.WriteByte('?')
	appendIfSet := func(k, v string) {
		if v == "" {
			return
		}
		sb.WriteString(url.QueryEscape(k))
		sb.WriteByte('=')
		sb.WriteString(url.QueryEscape(v))
		sb.WriteByte('&')
	}
	appendIfSet("range", rng)
	appendIfSet("ip", ipFilter)
	appendIfSet("ja4", ja4Filter)
	appendIfSet("ua", uaFilter)
	appendIfSet("phase", phase)
	// host can be repeated (= multi-select).
	for _, h := range q["host"] {
		appendIfSet("host", h)
	}
	// Rows-per-page rides along so paging keeps the operator's choice; the
	// default is omitted to keep classic URLs stable.
	if pageSize != 100 {
		appendIfSet("n", strconv.Itoa(pageSize))
	}
	// The freeze id has to travel with the paging links: drop it and the next
	// page is computed against a log that has grown since, which is the
	// duplicate-rows bug it exists to prevent.
	live := sb.String()
	if freezeID > 0 {
		appendIfSet("asof", strconv.FormatInt(freezeID, 10))
	}
	seek := buildPagerSeekData(lang, sb.String(), offset, pageSize, hasPrev, hasNext, rangeText)
	// "First" is the exception, and deliberately so: it is the way back to the
	// newest events.  Carrying the freeze there would leave an operator who
	// paged away with no link that shows the log moving again -- they would
	// have to notice the URL.  The range buttons drop it for the same reason
	// (they rebuild the query from scratch).
	seek.FirstURL = strings.TrimSuffix(live, "&")
	if seek.FirstURL == "" {
		seek.FirstURL = "?"
	}
	return seek
}

// ownedSessionRows trims a bled read (page window + rows on both sides, see
// events.FetchPagedWithBleed) down to the sessions this page owns, keeping
// every row of those sessions even where it came from outside the window.
//
// A page owns a session when the session's NEWEST row falls inside the window.
// Without that rule the boundary sessions would render on both adjacent pages
// -- complete on each, but counted twice and read as duplicates.  With it,
// every session appears exactly once and whole: the page holding its newest
// row reaches back for the rest, and the neighbour skips it entirely.
//
// Rows with no beacon token (forward-auth `check`, anything ingested before
// the token existed) are their own session of one, so they simply have to be
// inside the window.
//
// hasMore reports whether the underlying query reached past the window's far
// edge, which is what the pager needs -- the returned row count cannot answer
// that any more, since it now includes borrowed rows.
func ownedSessionRows(rows []events.Row, windowStart, pageSize int) (owned []events.Row, hasMore bool) {
	windowEnd := windowStart + pageSize
	if windowEnd > len(rows) {
		windowEnd = len(rows)
	}
	if windowStart > len(rows) {
		windowStart = len(rows)
	}
	hasMore = len(rows) > windowEnd

	// Rows arrive newest-first, so the first row carrying a token is that
	// session's newest -- and the session belongs to this page only if that
	// row is in the window.
	ownedTok := map[string]bool{}
	for i := 0; i < len(rows); i++ {
		tok := rows[i].BeaconToken
		if tok == "" {
			continue
		}
		if _, seen := ownedTok[tok]; seen {
			continue
		}
		ownedTok[tok] = i >= windowStart && i < windowEnd
	}

	owned = make([]events.Row, 0, windowEnd-windowStart)
	for i, r := range rows {
		if r.BeaconToken == "" {
			if i >= windowStart && i < windowEnd {
				owned = append(owned, r)
			}
			continue
		}
		if ownedTok[r.BeaconToken] {
			owned = append(owned, r)
		}
	}
	return owned, hasMore
}

// rankCardKeys: the folding keys, and the only values accepted from the cookie.
// Anything else is dropped rather than passed to the template -- the value is
// operator-supplied and ends up in a class name.
var rankCardKeys = []string{"ip", "asn", "ja4", "ua"}

// resolveRankFolded reads unmask_rank_fold (comma-separated card keys) into a
// lookup the template can ask by name.
//
// The four rank cards share one row, and the widest data decides how much is
// left for the others -- a JA4 column of 36-character hashes or a network with
// long organisation names can leave the UA card too narrow to read.  Folding a
// card the operator does not need at that moment hands its width back to the
// ones they do, and the choice persists because it is a standing preference,
// not a per-visit one.
func resolveRankFolded(r *http.Request) map[string]bool {
	out := map[string]bool{}
	c, err := r.Cookie("unmask_rank_fold")
	if err != nil {
		return out
	}
	valid := map[string]bool{}
	for _, k := range rankCardKeys {
		valid[k] = true
	}
	for _, part := range strings.Split(decodeCookieValue(c.Value), ",") {
		if k := strings.TrimSpace(part); valid[k] {
			out[k] = true
		}
	}
	return out
}

// dropFoldIfAllFolded: keep at least one card open.
//
// The cookie names cards, not the ones this page actually renders -- the
// network card is omitted without an ASN database -- so a cookie written on an
// install that had one folds every card that is left, and the row renders empty
// with no control to click and no way back except clearing the cookie.  The
// browser guard cannot help: it only stops the state being created here.
func dropFoldIfAllFolded(folded map[string]bool, rendered []string) map[string]bool {
	for _, k := range rendered {
		if !folded[k] {
			return folded
		}
	}
	return map[string]bool{}
}

// cookieIsSet: a flag cookie the UI writes as "1" and deletes to clear.
func cookieIsSet(r *http.Request, name string) bool {
	c, err := r.Cookie(name)
	return err == nil && decodeCookieValue(c.Value) == "1"
}
