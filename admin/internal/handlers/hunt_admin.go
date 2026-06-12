// bot-hunting tab: page through unmask_event to find bots and act with a single click.
//
// Structure:
//  1. Top N rankings for the last N minutes (= top 30 by IP / JA4 / UA, ordered by req count desc).
//     Each row carries [BAN now] / [UA blacklist] / [JA4 verdict bot] buttons.
//  2. Raw-log pager (= unmask_event in reverse chronological order, 100 / page).
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

// AdminHuntIndex: GET /admin/hunt/ — ranking + raw log + live tail.
func (h *Handler) AdminHuntIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	rng := q.Get("range")
	sinceMin := 60
	switch rng {
	case "1h", "":
		rng = "1h"
		sinceMin = 60
	case "6h":
		sinceMin = 360
	case "24h":
		sinceMin = 1440
	default:
		rng = "1h"
		sinceMin = 60
	}

	ipFilter := strings.TrimSpace(q.Get("ip"))
	ja4Filter := strings.TrimSpace(q.Get("ja4"))
	phaseFilter := strings.TrimSpace(q.Get("phase"))
	if !events.IsValidPhase(phaseFilter) {
		phaseFilter = ""
	}
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

	const pageSize = 100
	rows, err := events.FetchPaged(r.Context(), h.DB, ipFilter, ja4Filter, phaseFilter, siteFilter, hostFilters, sinceMin, pageSize, offset)
	if err != nil {
		log.Printf("hunt fetch: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Hosts / HostSelected / SelfHostID (= for the shared host_picker) are
	// injected by addMeToData, which is shared by every admin page.

	// Three ranking tables (= filters are not applied.  Top entries within
	// the tab's sinceMin window).
	ipRankRaw, _ := events.RankByIP(r.Context(), h.DB, sinceMin, 30)
	ja4RankRaw, _ := events.RankByJA4(r.Context(), h.DB, sinceMin, 30)
	uaRankRaw, _ := events.RankByUA(r.Context(), h.DB, sinceMin, 30)

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

	hasMore := len(rows) == pageSize

	// Attach country code + ban status to event rows.  The same IP appears
	// on multiple rows, so cache per IP (= avoid duplicate lookups).
	//   - CountryCode: empty when IP-geo is not loaded
	//   - Banned     : an active ban exists for this IP (= including full
	//                  wildcard).  Same semantics as IPRank
	//                  (= ja4 empty when calling IsBanned -> per-IP count).
	type huntEventRow struct {
		events.Row
		CountryCode string
		Banned      bool
	}
	enriched := make([]huntEventRow, 0, len(rows))
	geoOK := h.IPGeo != nil && h.IPGeo.Loaded()
	banOK := h.BanMgr != nil
	ipCC := map[string]string{}
	ipBan := map[string]bool{}
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
		enriched = append(enriched, huntEventRow{
			Row:         e,
			CountryCode: ipCC[e.IP],
			Banned:      ipBan[e.IP],
		})
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
			p := e.Row.Path
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

	data := map[string]any{
		"Lang":       i18n.Resolve(r),
		"TZ":         resolveTZ(r),
		"BasePath":   h.cfg().Server.BasePath,
		"Version":    h.Version,
		"Range":      rng,
		"SinceMin":   sinceMin,
		"IPFilter":   ipFilter,
		"JA4Filter":  ja4Filter,
		"Phase":      phaseFilter,
		"Rows":       enriched,
		"IPRank":     ipRank,
		"JA4Rank":    ja4Rank,
		"UARank":     uaRank,
		"Offset":     offset,
		"NextOffset": offset + pageSize,
		"PrevOffset": maxInt(offset-pageSize, 0),
		"HasMore":    hasMore,
		"HasPrev":    offset > 0,
		// Range caption fits the seek pager's right-hand info slot.  We don't
		// expose a total (= unmask_event would need a window-scoped COUNT(*)
		// that doesn't scale), but "N-M 件目を表示中" is cheap and useful.
		"PagerSeek": buildHuntPagerSeek(
			i18n.Resolve(r), rng, ipFilter, ja4Filter, phaseFilter, q,
			offset, pageSize, offset > 0, hasMore,
			huntRangeText(i18n.Resolve(r), offset, len(enriched)),
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

// huntRangeText builds the "N-M 件目を表示中" caption shown next to the seek
// pager.  No total -- the event table is too large for COUNT(*).  Empty
// when the page has no rows so the caption stays out of the way.
func huntRangeText(lang i18n.Lang, offset, gotRows int) string {
	if gotRows <= 0 {
		return ""
	}
	return i18n.Tf(lang, "pager.range_caption", offset+1, offset+gotRows)
}

// buildHuntPagerSeek builds a PagerSeekData for the hunt page.  The base
// query carries range / ip / ja4 / phase plus any host=... selections so
// pager links keep the operator's filters intact.
func buildHuntPagerSeek(lang i18n.Lang, rng, ipFilter, ja4Filter, phase string, q url.Values, offset, pageSize int, hasPrev, hasNext bool, rangeText string) PagerSeekData {
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
	appendIfSet("phase", phase)
	// host can be repeated (= multi-select).
	for _, h := range q["host"] {
		appendIfSet("host", h)
	}
	return buildPagerSeekData(lang, sb.String(), offset, pageSize, hasPrev, hasNext, rangeText)
}
