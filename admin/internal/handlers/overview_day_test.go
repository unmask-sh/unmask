package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The dashboard's 24-hour section: the pipeline card and the hourly chart on
// the page, the AI / crawler table gone (the stats page has it), and the same
// section alone when the page asks for its minute refresh.
func TestOverviewDaySection(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

	get := func(target string) string {
		rr := httptest.NewRecorder()
		h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, target, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d", target, rr.Code)
		}
		return rr.Body.String()
	}
	page := get("/unmask/admin/")
	for _, want := range []string{`id="day-section"`, `data-stage="requests"`, `data-stage="bypass"`, `data-stage="rl"`, `data-stage="serve"`, `data-stage="pass"`, `id="hourly-card"`, `id="comp-card"`, `class="meta kpi-note"`, `window.unmaskInitComp = function`, `window.unmaskRefreshDay = function`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Count(page, `class="pipe-st"`) != 5 {
		t.Errorf("%d pipeline stages, want 5", strings.Count(page, `class="pipe-st"`))
	}
	for _, gone := range []string{`table.ai-traffic`, `ai_traffic_card`, `class="ai-tabs"`, `class="kpi-grid"`} {
		if strings.Contains(page, gone) {
			t.Errorf("page still carries %q", gone)
		}
	}
	// The rate-limit stage has no rollup to read in this test: a dash, and
	// the line says why.
	if !strings.Contains(page, `data-stage="rl"`) || !strings.Contains(page, i18n.T("ja", "overview.pipe.rl_unknown")) {
		t.Error("the rate-limit stage must say its figure is not available here")
	}

	// The partial: the section alone, not the page.
	part := get("/unmask/admin/?partial=day")
	for _, want := range []string{`class="hero`, `id="comp-card"`, `id="hourly-card"`} {
		if !strings.Contains(part, want) {
			t.Errorf("partial lacks %q", want)
		}
	}
	for _, gone := range []string{`<html`, `id="live-grid"`, `id="day-section"`, `<script`, `overview.recent_h`, `window.unmaskInitComp`} {
		if strings.Contains(part, gone) {
			t.Errorf("partial carries %q", gone)
		}
	}
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/?partial=day", nil))
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("the partial must not be cached: %q", rr.Header().Get("Cache-Control"))
	}
}

func TestHourlyViewGeometry(t *testing.T) {
	var hc dashboard.HourlyCompare
	hc.OK = true
	hc.NowHour = 10
	hc.Today[10] = 50
	hc.Yesterday[10] = 100
	hc.Yesterday[23] = 25
	v := hourly("ja", hc)
	if !v.OK || v.Max != 100 || len(v.Bars) != 24 || !strings.Contains(v.MaxText, "100") {
		t.Fatalf("view: ok=%v max=%d bars=%d maxText=%q", v.OK, v.Max, len(v.Bars), v.MaxText)
	}
	b := v.Bars[10]
	if !b.Now || b.Future || b.YH != hourlyPlotH || b.TH != hourlyPlotH/2 || b.TY != hourlyBase-hourlyPlotH/2 {
		t.Errorf("hour 10: %+v", b)
	}
	if !v.Bars[11].Future || v.Bars[11].TH != 0 || v.Bars[23].YH != hourlyPlotH/4 {
		t.Errorf("hours 11/23: %+v %+v", v.Bars[11], v.Bars[23])
	}
	if v.Bars[0].X != 0 || v.Bars[1].X <= v.Bars[0].X || v.Bars[1].XC <= v.Bars[1].X {
		t.Errorf("x layout: %+v %+v", v.Bars[0], v.Bars[1])
	}
	// Nothing counted: no bars drawn at all, and no division by zero.
	empty := hourly("en", dashboard.HourlyCompare{})
	if empty.OK || empty.Max != 0 || empty.Bars[5].YH != 0 {
		t.Errorf("empty: %+v", empty.Bars[5])
	}
}

func TestPipelineStages(t *testing.T) {
	comp := dashboard.TrafficComposition{Total: 1000, Benign: 100, Bypassed: 50, Challenged: 300, PowPass: 400, CaptchaPass: 20, OK: true}
	st := pipeline("ja", comp, 300, 410, 25, 15, 420, true, true, 7, true)
	keys := []string{"requests", "bypass", "rl", "serve", "pass"}
	for i, k := range keys {
		if st[i].Key != k || !st[i].Known {
			t.Errorf("stage %d = %+v, want %s known", i, st[i], k)
		}
	}
	if st[0].N != 1000 || st[1].N != 150 || st[2].N != 7 || st[3].N != 300 || st[4].N != 435 {
		t.Errorf("counts: %d %d %d %d %d", st[0].N, st[1].N, st[2].N, st[3].N, st[4].N)
	}
	if !strings.Contains(st[1].Sub, "100") || !strings.Contains(st[1].Sub, "50") {
		t.Errorf("bypass sub: %q", st[1].Sub)
	}
	if !strings.Contains(st[4].Sub, "410") || !strings.Contains(st[4].Sub, "25") || !strings.Contains(st[4].Sub, "15") || !strings.Contains(st[4].Sub, "420") {
		t.Errorf("pass sub: %q", st[4].Sub)
	}
	// Without the feed: the request-based stages are unknown and say so; the
	// passed stage's line says the cookie share is missing.
	none := pipeline("en", dashboard.TrafficComposition{}, 300, 15, 10, 25, 0, false, true, 0, false)
	if none[0].Known || none[1].Known || none[2].Known || !none[3].Known || !none[4].Known {
		t.Errorf("known flags without the feed: %+v", none)
	}
	if !strings.Contains(none[4].Sub, "access-log") || !strings.Contains(none[2].Sub, "not available") {
		t.Errorf("subs without the feed: %q / %q", none[4].Sub, none[2].Sub)
	}
	_ = time.Now
}
