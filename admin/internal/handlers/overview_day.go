package handlers

import (
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The dashboard's 24-hour section: the pipeline card's stages and the hourly
// today/yesterday chart.  The server renders both, for the page and again for
// the section's minute refresh (?partial=day), so the two never disagree.

// pipeStage is one stage of the pipeline card, in the order requests pass
// through them.
type pipeStage struct {
	Key      string // requests / bypass / rl / serve / solve / pass
	LabelKey string
	HelpKey  string // "" = no help tip
	Sub      string // the line under the figure, worded here
	Color    string
	N        int
	Known    bool // false renders a dash with Sub saying why
}

// pipeline lays the 24-hour numbers the handler already has out as stages.
// Shares are computed by the template against the request total.
//
// The passed stage counts requests, like every other stage: the solves plus
// the requests admitted on the cookies those solves minted, split by method
// on the first line and by solve/cookie on the second (the operator's 2026-09-09
// call: a headline of solves alone beside "challenges served" read as almost
// nothing passing).  Without the access-log feed the cookie share is unknown,
// the headline is the solves alone and the stage says so.
func pipeline(lang i18n.Lang, comp dashboard.TrafficComposition, fired, powTotal, captchaTotal, solves, cookies int, cookieKnown, kpiKnown bool, rl int, rlKnown bool) []pipeStage {
	t := func(k string) string { return i18n.T(lang, k) }
	tf := func(k string, a ...any) string { return i18n.Tf(lang, k, a...) }
	passSub := tf("overview.pipe.pass_sub", commaStr(powTotal), commaStr(captchaTotal)) + " · "
	if cookieKnown {
		passSub += tf("overview.kpi.pass_breakdown", commaStr(solves), commaStr(cookies))
	} else {
		passSub += tf("overview.kpi.pass_solves_only", commaStr(solves))
	}
	stages := []pipeStage{
		{Key: "requests", LabelKey: "overview.pipe.requests", Sub: t("overview.pipe.requests_sub"), Color: "#0f172a", N: comp.Total, Known: comp.OK},
		{Key: "bypass", LabelKey: "overview.pipe.bypass", HelpKey: "overview.live.bypass_help", Sub: tf("overview.pipe.bypass_sub", commaStr(comp.Benign), commaStr(comp.Bypassed)), Color: "#6366f1", N: comp.Benign + comp.Bypassed, Known: comp.OK},
		{Key: "rl", LabelKey: "overview.pipe.rl", HelpKey: "overview.live.rate_limit_help", Sub: t("overview.pipe.rl_sub"), Color: "#f59e0b", N: rl, Known: rlKnown},
		{Key: "serve", LabelKey: "overview.kpi.serves", HelpKey: "overview.live.serve_help", Sub: t("overview.kpi.serves_sub"), Color: "#dc2626", N: fired, Known: kpiKnown},
		{Key: "pass", LabelKey: "overview.pipe.pass", HelpKey: "overview.pipe.pass_help", Sub: passSub, Color: "#16a34a", N: powTotal + captchaTotal, Known: kpiKnown},
	}
	if !rlKnown {
		stages[2].Sub = t("overview.pipe.rl_unknown")
	}
	if !comp.OK {
		for i := range stages {
			if stages[i].Key == "requests" || stages[i].Key == "bypass" {
				stages[i].Sub = t("overview.kpi.nonhuman_nodata")
			}
		}
	}
	return stages
}

// commaStr is the template's comma for Go-side wording.
func commaStr(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// Chart geometry, shared with the template's SVG: a 1400×170 box, bars rising
// from y=150, each hour a 58.33-wide group with yesterday's bar at +9 and
// today's at +31, both 18 wide.
const (
	hourlyW     = 1400.0
	hourlyPlotH = 146.0
	hourlyBase  = 150.0
)

type hourBar struct {
	H                int
	Today, Yesterday int
	X                float64 // the group's left edge
	XY, XT, XC       float64 // yesterday's bar, today's bar, the hour label's centre
	TH, YH           float64 // bar heights in SVG units
	TY, YY           float64 // bar tops (hourlyBase minus height)
	Now              bool    // the hour the reading was taken in
	Future           bool    // today's hours not yet reached: no bar
}

type hourlyView struct {
	OK      bool
	Max     int
	MaxText string
	Bars    []hourBar
}

// hourly lays the two days out for the SVG.
func hourly(lang i18n.Lang, hc dashboard.HourlyCompare) hourlyView {
	v := hourlyView{OK: hc.OK}
	for h := 0; h < 24; h++ {
		if hc.Today[h] > v.Max {
			v.Max = hc.Today[h]
		}
		if hc.Yesterday[h] > v.Max {
			v.Max = hc.Yesterday[h]
		}
	}
	v.MaxText = i18n.Tf(lang, "overview.hourly.max", commaStr(v.Max))
	scale := func(n int) float64 {
		if v.Max == 0 || n == 0 {
			return 0
		}
		return float64(n) / float64(v.Max) * hourlyPlotH
	}
	for h := 0; h < 24; h++ {
		b := hourBar{H: h, Today: hc.Today[h], Yesterday: hc.Yesterday[h], X: float64(h) * hourlyW / 24, Now: h == hc.NowHour, Future: h > hc.NowHour}
		b.XY, b.XT, b.XC = b.X+9, b.X+31, b.X+hourlyW/48
		b.YH = scale(b.Yesterday)
		b.YY = hourlyBase - b.YH
		if !b.Future {
			b.TH = scale(b.Today)
		}
		b.TY = hourlyBase - b.TH
		v.Bars = append(v.Bars, b)
	}
	return v
}
