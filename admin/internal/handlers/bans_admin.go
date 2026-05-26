// Persistent BAN tab: management screen for shared infrastructure used by
// multiple features (= honeypot / manual / future protected_failed etc.).
// admin role or higher can view / operate.
//
// Dispatch by op parameter:
//
//	op=add              : manual add with ip + ja4 + reason + duration_sec
//	op=delete           : unban by id
//	op=subscribe-toggle : turn the shared feed subscribe (= pull) ON/OFF.  Top-right toggle only
//
// The honeypot-derived default TTL (= ban_duration) has been moved to settings/?tab=honeypot.
// Detailed shared-feed settings (terms / submit / URL override etc.) live in settings/?tab=shared-feed.
// The bans page is intentionally a shortcut UX that triggers only **subscribe (= receive)**.
package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/sharedfeed"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// AdminBansIndex: GET /admin/bans/ — BAN list + manual-add form + shared-feed browse.
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
	for _, e := range entries {
		banRows = append(banRows, banRow{Entry: e, CountryCode: lookupCC(e.IP)})
	}

	// === shared-feed browse: migrated from /admin/shared-feed/ ===
	cur := h.snapshotSettings()
	mapDir := strings.TrimSpace(cur.SharedFeed.MapDir)
	if mapDir == "" {
		mapDir = strings.TrimSpace(cur.Nginx.OutputDir)
	}
	if mapDir == "" {
		mapDir = "/etc/unmask"
	}
	doc, err := sharedfeed.ReadDocument(mapDir)
	if err != nil {
		log.Printf("bans: shared-feed read doc: %v", err)
		// keep rendering (= treat as empty doc).
	}
	match := strings.TrimSpace(r.URL.Query().Get("match"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	// FeedEntry + CountryCode (= for the flag rendered to the left of the IP popover).
	type feedRow struct {
		sharedfeed.FeedEntry
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
		case sharedfeed.MatchIPJA4:
			countIPJA4++
		case sharedfeed.MatchJA4:
			countJA4++
		case sharedfeed.MatchIPOnly:
			countIP++
		}
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
		"SubscribeEnabled":       cur.SharedFeed.SubscribeEnabled,
		"SharedFeedLastPulledAt": cur.SharedFeed.LastPulledAt,
		"SharedFeedGeneratedAt":  doc.GeneratedAt,
		"SharedFeedVersion":      doc.Version,
		"SharedFeedEntries":      filtered,
		"SharedFeedTotalEntries": len(doc.Entries),
		"SharedFeedFiltered":     len(filtered),
		"SharedFeedCountIPJA4":   countIPJA4,
		"SharedFeedCountJA4":     countJA4,
		"SharedFeedCountIP":      countIP,
		"SharedFeedMatch":        match,
		"SharedFeedQuery":        q,
		"SharedFeedMapDir":       mapDir,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "bans.html", data); err != nil {
		log.Printf("bans render: %v", err)
	}
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
	redir := func(msg string) {
		dst := base + "/admin/bans/"
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
		// Bans-page-inline editor for the per-source default action.  Lives on
		// /admin/bans/ alongside the BAN list so operators don't have to dig
		// into the honeypot tab to set "manual / shared_feed default".
		manualAct := strings.TrimSpace(r.FormValue("bans_manual_default_action"))
		sharedAct := strings.TrimSpace(r.FormValue("bans_shared_feed_default_action"))
		cur, err := settings.Load(h.ConfigPath)
		if err != nil {
			redir("load: " + err.Error())
			return
		}
		if manualAct != "" && !settings.IsValidRateChallengeMode(manualAct) {
			manualAct = ""
		}
		if sharedAct != "" && !settings.IsValidRateChallengeMode(sharedAct) {
			sharedAct = ""
		}
		cur.Nginx.Bans.ManualDefaultAction = manualAct
		cur.Nginx.Bans.SharedFeedDefaultAction = sharedAct
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
				"", fmt.Sprintf(`{"manual":%q,"shared_feed":%q}`, manualAct, sharedAct))
		}
		redir("")
		return

	case "subscribe-toggle":
		// Turn shared-feed subscribe (= pull) ON/OFF.  Top-right toggle only.
		// terms / submit / URL override etc. live in settings/?tab=shared-feed.
		want := r.FormValue("subscribe_enabled") == "1"
		cur, err := settings.Load(h.ConfigPath)
		if err != nil {
			redir("load: " + err.Error())
			return
		}
		cur.SharedFeed.SubscribeEnabled = want
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
		// (= sharedfeed.Submit has a sync retry too, but get it ahead of time here).
		if want && h.SharedFeed != nil && strings.TrimSpace(cur.SharedFeed.Token) == "" {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				if err := h.SharedFeed.Register(ctx); err != nil {
					log.Printf("sharedfeed: subscribe-toggle register: %v", err)
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
