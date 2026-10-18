package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/live"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The dashboard's "right now" strip: one tile per entry of liveTiles, each
// with the last thirty minutes' count, the last minute's, and a bar a minute.
// Seven tiles are kinds; the blocked tile is the figure derived from them
// (the dashboard's headline, what the map draws by default).  The abandoned
// proofs-of-work have no tile of their own: they are a term of that figure.
// The page renders the strip with a first reading (so it says real numbers
// before any script runs) and then re-reads /admin/api/now every few seconds,
// replacing the figures in place.

// liveTile is one tile as the template draws it.
type liveTile struct {
	Key       string // live.Names entry: the JSON key the script updates from
	LabelKey  string // i18n key of the tile's name
	HelpKey   string // i18n key of its help text
	Color     string // the kind's colour, the same one the stats charts use
	Last      int    // the last live.Window seconds
	Last30    int    // the last live.Minutes minutes: the tile's headline
	Bars      []liveBar
	Points    string // SVG polyline points of the series
	TPS       string // requests only: "1.6 · 8.6 · 2.5" as three strings
	Peak, Avg string
}

type liveView struct {
	Scope   string // liveScopeJudged or liveScopeAll: what the requests tile counts
	Tiles   []liveTile
	FeedOff bool   // no access-log feed configured and nothing ever counted
	At      string // the reading's clock time, HH:MM:SS in the picker's zone
	AtTS    int64  // the same instant as unix seconds, for the script's clock
}

// liveTiles lists the tiles in display order with their colours: the kind
// colours of the stats page's stacked charts (KIND_COLOR) where one exists,
// the map legend's blocked colour for the blocked tile.  The blocked figure
// comes right after the requests, as the dashboard's headline does; then
// what was let through, then the gate's answers, the refusals beside the
// challenges.  Two rows of four on a laptop: the first row what came and
// what became of it, the second the gate.
var liveTiles = []struct {
	key   string // live.Names entry or live.BlockedName: the JSON key, the i18n key's tail
	color string
}{
	{live.Names[live.Requests], "#0f172a"},
	{live.BlockedName, "#f87171"},
	{live.Names[live.Pass], "#94a3b8"},
	{live.Names[live.Bypass], "#c7d2fe"},
	{live.Names[live.Serve], "#dc2626"},
	{live.Names[live.Deny], "#7f1d1d"},
	{live.Names[live.Solve], "#0ea5e9"},
	{live.Names[live.RateLimit], "#f59e0b"},
}

// liveFigures is one tile's reading: a kind's counters, or for the blocked
// tile the figure derived from them.
func liveFigures(sn *live.Snapshot, key string) (last, last30 uint32, minutes, series []uint32) {
	if key == live.BlockedName {
		return sn.Blocked.Last, sn.Blocked.Last30, sn.Blocked.PerMinute[:], sn.Blocked.Series[:]
	}
	for k := live.Kind(0); k < live.NumKinds; k++ {
		if live.Names[k] == key {
			return sn.Last[k], sn.Last30[k], sn.PerMinute[k][:], sn.Series[k][:]
		}
	}
	return 0, 0, nil, nil
}

// liveView builds the strip's first reading.  tzName is the picker's zone
// (resolveTZ); unknown or empty reads as UTC.
func (h *Handler) liveView(now time.Time, tzName, scope string) liveView {
	sn := h.Live.Snapshot(now)
	loc := time.UTC
	if tzName != "" {
		if l, err := time.LoadLocation(tzName); err == nil {
			loc = l
		}
	}
	v := liveView{At: now.In(loc).Format("15:04:05"), AtTS: now.Unix(), Scope: scope}
	v.FeedOff = !h.cfg().NginxLog.Enabled && sn.LastLine == 0
	for _, lt := range liveTiles {
		last, last30, minutes, series := liveFigures(&sn, lt.key)
		judged := lt.key == live.Names[live.Requests] && scope == liveScopeJudged
		if judged {
			last, last30, minutes, series = liveJudged(&sn)
		}
		t := liveTile{
			Key:      lt.key,
			LabelKey: "overview.live." + lt.key,
			HelpKey:  "overview.live." + lt.key + "_help",
			Color:    lt.color,
			Last:     int(last),
			Last30:   int(last30),
			Bars:     liveBarGeom(minutes),
			Points:   liveSparkPoints(series),
		}
		if lt.key == live.Names[live.Requests] {
			t.TPS, t.Peak, t.Avg = rate(sn.TPS), rate(sn.Peak), rate(sn.Avg)
			if judged {
				t.LabelKey = "overview.live.requests_judged"
				tps, peak, avg := liveRates(series)
				t.TPS, t.Peak, t.Avg = rate(tps), rate(peak), rate(avg)
			}
		}
		v.Tiles = append(v.Tiles, t)
	}
	return v
}

func rate(f float64) string { return fmt.Sprintf("%.1f", f) }

// The strip's scope: what its requests tile counts.  Judged (the default)
// leaves out the requests a bypass let through unjudged, as the dashboard's
// composition card does by default; all is every request nginx handled.
// ?scope= switches it and the cookie keeps the choice, as the card's does.
const (
	liveScopeCookieName = "unmask_live_scope"
	liveScopeJudged     = "judged"
	liveScopeAll        = "all"
)

// resolveLiveScope reads the strip's scope: the query parameter (a toggle
// link, before the cookie it sets is read back), then the cookie, then the
// default.  Anything else is the default, not an error.
func resolveLiveScope(r *http.Request) string {
	if r != nil {
		if v := r.URL.Query().Get("scope"); v == liveScopeAll || v == liveScopeJudged {
			return v
		}
		if c, err := r.Cookie(liveScopeCookieName); err == nil && c != nil {
			if v := decodeCookieValue(c.Value); v == liveScopeAll || v == liveScopeJudged {
				return v
			}
		}
	}
	return liveScopeJudged
}

// liveJudged is the requests tile's reading without the bypassed requests:
// each figure of the requests kind less the same figure of the bypass kind,
// never below zero (the two are counted from the same lines, so they cannot
// cross, but a reading taken between two increments must not go negative).
func liveJudged(sn *live.Snapshot) (last, last30 uint32, minutes, series []uint32) {
	sub := func(a, b uint32) uint32 {
		if a > b {
			return a - b
		}
		return 0
	}
	last = sub(sn.Last[live.Requests], sn.Last[live.Bypass])
	last30 = sub(sn.Last30[live.Requests], sn.Last30[live.Bypass])
	minutes = make([]uint32, len(sn.PerMinute[live.Requests]))
	for i := range minutes {
		minutes[i] = sub(sn.PerMinute[live.Requests][i], sn.PerMinute[live.Bypass][i])
	}
	series = make([]uint32, len(sn.Series[live.Requests]))
	for i := range series {
		series[i] = sub(sn.Series[live.Requests][i], sn.Series[live.Bypass][i])
	}
	return last, last30, minutes, series
}

// liveRates is the Snapshot's TPS / Peak / Avg for any series: the last
// bucket's rate, the busiest bucket's, and the mean over the span.
func liveRates(series []uint32) (tps, peak, avg float64) {
	if len(series) == 0 {
		return 0, 0, 0
	}
	var total, max uint32
	for _, v := range series {
		total += v
		if v > max {
			max = v
		}
	}
	return float64(series[len(series)-1]) / float64(live.Step), float64(max) / float64(live.Step), float64(total) / float64(live.Span)
}

// liveBar is one minute's bar of a tile's chart: the same 150×34 box as the
// sparkline, a 4-unit bar in each 5-unit slot, the top 2 left free, a bar
// of zero height for a minute without hits.
type liveBar struct {
	X, Y, H float64
}

func liveBarGeom(vals []uint32) []liveBar {
	if len(vals) == 0 {
		return nil
	}
	var max uint32
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	slot := sparkW / float64(len(vals))
	out := make([]liveBar, len(vals))
	for i, v := range vals {
		h := 0.0
		if max > 0 {
			h = float64(v) / float64(max) * (sparkH - 4)
		}
		out[i] = liveBar{X: float64(i) * slot, Y: sparkH - 2 - h, H: h}
	}
	return out
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
//	 "series": {"requests": [60 ints], ..., "blocked": [60 ints]}, "last": {"requests": n, ..., "blocked": n},
//	 "tps": {"now": 1.6, "peak": 8.6, "avg": 2.5},
//	 "countries": {"JP": {"n":148,"pass":100,"bypass":3,"serve":40,"deny":5,
//	               "solve":31,"abandon":2,"blocked":12,"people":33}},
//	 "minutes": {"requests": [30 ints], ...}, "minutes_n": 30, "last30": {"requests": n, ...},
//	 "countries30": {"JP": {...}},
//	 "country_names": {"JP": "Japan (日本)"},
//	 "refused30": {"asn_deny": 812, "banned": 40},
//	 "refused_rules30": {"asn_deny": [{"rule": "AS16509", "n": 700, "label": "AS16509"}, ...]},
//	 "refused_names": {"asn_deny": "ASN で遮断", ...},
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
		minutes := map[string][]uint32{}
		last30 := map[string]uint32{}
		for k := live.Kind(0); k < live.NumKinds; k++ {
			series[live.Names[k]] = sn.Series[k][:]
			last[live.Names[k]] = sn.Last[k]
			minutes[live.Names[k]] = sn.PerMinute[k][:]
			last30[live.Names[k]] = sn.Last30[k]
		}
		// The blocked figure, derived from the kinds above, under a key of its
		// own in each of the four: the page refreshes its tile like the rest.
		series[live.BlockedName] = sn.Blocked.Series[:]
		last[live.BlockedName] = sn.Blocked.Last
		minutes[live.BlockedName] = sn.Blocked.PerMinute[:]
		last30[live.BlockedName] = sn.Blocked.Last30
		out["series"] = series
		out["last"] = last
		out["minutes"] = minutes
		out["minutes_n"] = live.Minutes
		out["last30"] = last30
		out["countries30"] = sn.Countries30
		out["tps"] = map[string]float64{"now": sn.TPS, "peak": sn.Peak, "avg": sn.Avg}
		out["countries"] = sn.Countries
		// Each source's full name, for the map's popover: worded once here
		// rather than shipping the country table to the page.
		names := make(map[string]string, len(sn.Countries30))
		for cc := range sn.Countries30 {
			names[cc] = ipgeo.CountryName(cc)
		}
		for cc := range sn.Countries {
			names[cc] = ipgeo.CountryName(cc)
		}
		out["country_names"] = names
		// What was refused outright, and on which rule: the busiest few rules
		// of each reason, each reason named the way the dashboard's reasons
		// card names it.
		lang := i18n.Lang(i18n.Resolve(r))
		// The requests tile's reading without the bypassed requests, for the
		// strip's judged scope: the four figures and the rate caption, worded
		// here like tps_text below.
		jl, jl30, jm, js := liveJudged(&sn)
		jt, jp, ja := liveRates(js)
		out["requests_judged"] = map[string]any{
			"last": jl, "last30": jl30, "minutes": jm, "series": js,
			"tps_text": i18n.Tf(lang, "overview.live.tps", rate(jt), rate(jp), rate(ja)),
		}
		cfg := h.cfg()
		rules := map[string][]refusedRule{}
		reasonNames := map[string]string{}
		for reason := range sn.Refused30 {
			reasonNames[reason] = reasonLabel(lang, reason)
			rules[reason] = topRules(reason, sn.Rules30[reason], 3, cfg.Nginx.CustomRules)
		}
		out["refused30"] = sn.Refused30
		out["refused_rules30"] = rules
		out["refused_names"] = reasonNames
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

// refusedRule is one matching rule of a refusal reason: the rule as the
// event names it (an AS number, a country code, a custom rule's id), how many
// requests it refused, and what to call it on the page.
type refusedRule struct {
	Rule  string `json:"rule"`
	N     uint32 `json:"n"`
	Label string `json:"label"`
}

// topRules: the n busiest rules of one reason, busiest first (ties by rule,
// so the order holds still between readings).  A custom rule is called by its
// name where it has one: its id is what the log carries, not what the operator
// typed.
func topRules(reason string, m map[string]uint32, n int, custom []settings.CustomRule) []refusedRule {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	out := make([]refusedRule, 0, len(keys))
	for _, k := range keys {
		label := k
		if reason == "custom_rule" {
			for _, cr := range custom {
				if cr.ID == k && strings.TrimSpace(cr.Label) != "" {
					label = strings.TrimSpace(cr.Label)
				}
			}
		}
		out = append(out, refusedRule{Rule: k, N: m[k], Label: label})
	}
	return out
}
