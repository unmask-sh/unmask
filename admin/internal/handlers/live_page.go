package handlers

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The realtime page: the last thirty minutes, read every five seconds --
// the strip of tiles with a bar per minute, the map of sources, and the
// recent detections redrawn every few seconds.  The dashboard reads the
// day and keeps one line of now that points here.

// recentRow is one row of the recent-detections table: the event with the
// country its address resolves to and whether the address is banned, the
// shape the shared events partial reads.
type recentRow struct {
	events.Row
	CountryCode string
	Banned      bool
}

// recentDetections fetches the latest raw rows (40, so the page's session
// collapse still shows about ten sessions) and tags each with its country
// and ban state.
func (h *Handler) recentDetections(ctx context.Context, site string, hosts []string) ([]recentRow, error) {
	raw, err := events.FetchPaged(ctx, h.DB, "", "", "", "", "", "", site, hosts, 0, 40, 0)
	if err != nil {
		return nil, err
	}
	geoOK := h.IPGeo != nil && h.IPGeo.Loaded()
	banOK := h.BanMgr != nil
	ccCache := map[string]string{}
	banCache := map[string]bool{}
	out := make([]recentRow, 0, len(raw))
	for _, r0 := range raw {
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
		out = append(out, recentRow{Row: r0, CountryCode: cc, Banned: banned})
	}
	return out, nil
}

// AdminLive: GET {base}/admin/live/ -- the realtime page; ?partial=recent
// renders the recent-detections table alone for its redraw.
func (h *Handler) AdminLive(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	hosts := resolveHostFilter(r)
	site := resolveSiteFilter(r)
	recent, err := h.recentDetections(ctx, site, hosts)
	if err != nil {
		log.Printf("live recent: %v", err)
	}
	uaList := make([]string, len(recent))
	sites := make([]string, 0, len(recent))
	for i, row := range recent {
		uaList[i] = row.UA
		sites = append(sites, row.Site)
	}
	_, ghostSites := siteBadgeState(sites, h.snapshotSettings())
	data := map[string]any{
		"Lang":     i18n.Resolve(r),
		"TZ":       resolveTZ(r),
		"BasePath": h.cfg().Server.BasePath,
		"Version":  h.Version,
		// The shared events partial reads Rows / EventsCap / Range; EventsCap
		// caps the sessions shown after the client-side collapse.  No per-row
		// action column here: the hunt page is the place to act.
		"Recent":         recent,
		"Rows":           recent,
		"RowsGhostSites": ghostSites,
		"UABotNote":      uaBotNoteByUA(uaList, h.snapshotSettings().Nginx),
		"EventsCap":      10,
		"Range":          "",
		"HideActions":    true,
	}
	// The strip and the map: rendered with a first reading, so the page says
	// real numbers before its script runs, then refreshed from /admin/api/now.
	if h.Live != nil {
		lv := h.liveView(time.Now(), resolveTZ(r))
		data["LiveTiles"] = lv.Tiles
		data["LiveFeedOff"] = lv.FeedOff
		data["LiveAt"] = lv.At
		data["LiveAtTS"] = lv.AtTS
		data["MapLoc"] = h.mapLocation()
		data["MapAuto"] = h.autoMapLocation()
		data["GeoKnown"] = h.IPGeo != nil && h.IPGeo.Loaded()
		pay := SessionFromContext(r)
		data["CanEditMap"] = pay != nil && roleAtLeast(pay.Role, "admin")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if r.URL.Query().Get("partial") == "recent" {
		w.Header().Set("Cache-Control", "no-store")
		if err := tmpl.ExecuteTemplate(w, "live_recent", data); err != nil {
			log.Printf("live recent render: %v", err)
		}
		return
	}
	if err := tmpl.ExecuteTemplate(w, "live.html", data); err != nil {
		log.Printf("live render: %v", err)
	}
}
