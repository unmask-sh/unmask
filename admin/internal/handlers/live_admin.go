package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/live"
)

// The dashboard's "right now" strip: one tile per live.Kind, each with the
// last minute's count, its change against the minute before, and a five-minute
// sparkline.  The page renders the strip with a first reading (so it says real
// numbers before any script runs) and then re-reads /admin/api/now every few
// seconds, replacing the figures in place.

// liveTile is one tile as the template draws it.
type liveTile struct {
	Key        string // live.Names entry: the JSON key the script updates from
	LabelKey   string // i18n key of the tile's name
	HelpKey    string // i18n key of its help text
	Color      string // the kind's colour, the same one the stats charts use
	Last       int    // the last live.Window seconds
	Delta      int    // Last minus the window before
	DeltaText  string // "+12" / "-3" / "±0"
	DeltaClass string // "up" / "down" / ""
	Points     string // SVG polyline points of the series
	TPS        string // requests only: "1.6 · 8.6 · 2.5" as three strings
	Peak, Avg  string
}

type liveView struct {
	Tiles   []liveTile
	FeedOff bool   // no access-log feed configured and nothing ever counted
	At      string // the reading's clock time, HH:MM:SS in the picker's zone
	AtTS    int64  // the same instant as unix seconds, for the script's clock
}

// liveKinds lists the tiles in display order with their colours: the kind
// colours of the stats page's stacked charts (KIND_COLOR) where one exists.
var liveKinds = []struct {
	kind  live.Kind
	color string
}{
	{live.Requests, "#0f172a"},
	{live.Pass, "#94a3b8"},
	{live.Bypass, "#c7d2fe"},
	{live.Serve, "#dc2626"},
	{live.Solve, "#0ea5e9"},
	{live.Deny, "#7f1d1d"},
	{live.RateLimit, "#f59e0b"},
}

// liveView builds the strip's first reading.  tzName is the picker's zone
// (resolveTZ); unknown or empty reads as UTC.
func (h *Handler) liveView(now time.Time, tzName string) liveView {
	sn := h.Live.Snapshot(now)
	loc := time.UTC
	if tzName != "" {
		if l, err := time.LoadLocation(tzName); err == nil {
			loc = l
		}
	}
	v := liveView{At: now.In(loc).Format("15:04:05"), AtTS: now.Unix()}
	v.FeedOff = !h.cfg().NginxLog.Enabled && sn.LastLine == 0
	for _, lk := range liveKinds {
		k := lk.kind
		t := liveTile{
			Key:      live.Names[k],
			LabelKey: "overview.live." + live.Names[k],
			HelpKey:  "overview.live." + live.Names[k] + "_help",
			Color:    lk.color,
			Last:     int(sn.Last[k]),
			Delta:    int(sn.Last[k]) - int(sn.Prev[k]),
			Points:   liveSparkPoints(sn.Series[k][:]),
		}
		t.DeltaText, t.DeltaClass = deltaText(t.Delta)
		if k == live.Requests {
			t.TPS, t.Peak, t.Avg = rate(sn.TPS), rate(sn.Peak), rate(sn.Avg)
		}
		v.Tiles = append(v.Tiles, t)
	}
	return v
}

func rate(f float64) string { return fmt.Sprintf("%.1f", f) }

func deltaText(d int) (string, string) {
	switch {
	case d > 0:
		return fmt.Sprintf("+%d", d), "up"
	case d < 0:
		return fmt.Sprintf("%d", d), "down"
	}
	return "±0", ""
}

// Sparkline geometry, shared with the script that redraws it: a 150×34 box,
// the top 2px and bottom 2px left free, a flat line along the bottom when
// every bucket is zero.
const sparkW, sparkH = 150.0, 34.0

func liveSparkPoints(vals []uint32) string {
	if len(vals) == 0 {
		return ""
	}
	var max uint32
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for i, v := range vals {
		x := float64(i) * (sparkW / float64(len(vals)-1))
		y := sparkH - 2
		if max > 0 {
			y = sparkH - 2 - float64(v)/float64(max)*(sparkH-6)
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String()
}

// AdminNowJSON: GET {base}/admin/api/now -- the live strip's reading, for the
// page to refresh its tiles (and the map) in place.
//
//	{"at": unix, "step": 5, "span": 300, "window": 60, "available": true,
//	 "series": {"requests": [60 ints], ...}, "last": {"requests": n, ...},
//	 "prev": {...}, "tps": {"now": 1.6, "peak": 8.6, "avg": 2.5},
//	 "countries": {"JP": {"n":148,"pass":100,"bypass":3,"serve":40,"deny":5}},
//	 "country_names": {"JP": "Japan (日本)"},
//	 "feed_off": false, "bans": 9}
//
// Read-only, cheap (an in-memory ring), and answered for every signed-in role:
// it carries nothing the dashboard itself does not show.
func (h *Handler) AdminNowJSON(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	out := map[string]any{
		"at":        now.Unix(),
		"step":      live.Step,
		"span":      live.Span,
		"window":    live.Window,
		"available": h.Live != nil,
	}
	if h.Live != nil {
		sn := h.Live.Snapshot(now)
		series := map[string][]uint32{}
		last := map[string]uint32{}
		prev := map[string]uint32{}
		for k := live.Kind(0); k < live.NumKinds; k++ {
			series[live.Names[k]] = sn.Series[k][:]
			last[live.Names[k]] = sn.Last[k]
			prev[live.Names[k]] = sn.Prev[k]
		}
		out["series"] = series
		out["last"] = last
		out["prev"] = prev
		out["tps"] = map[string]float64{"now": sn.TPS, "peak": sn.Peak, "avg": sn.Avg}
		out["countries"] = sn.Countries
		// Each source's full name, for the map's popover: worded once here
		// rather than shipping the country table to the page.
		names := make(map[string]string, len(sn.Countries))
		for cc := range sn.Countries {
			names[cc] = ipgeo.CountryName(cc)
		}
		out["country_names"] = names
		out["feed_off"] = !h.cfg().NginxLog.Enabled && sn.LastLine == 0
		// The request tile's caption, pre-worded here so the script does not
		// carry the format strings of every language.
		out["tps_text"] = i18n.Tf(i18n.Lang(i18n.Resolve(r)), "overview.live.tps", rate(sn.TPS), rate(sn.Peak), rate(sn.Avg))
	}
	if h.BanMgr != nil {
		out["bans"] = len(h.BanMgr.Snapshot())
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}
