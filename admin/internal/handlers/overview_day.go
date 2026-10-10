package handlers

import (
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The dashboard's 24-hour section: the tiles are rendered straight from the
// handler's figures by the template; the hourly today/yesterday chart is laid
// out here.  The server renders the section for the page and again for its
// minute refresh (?partial=day), so the two never disagree.

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
