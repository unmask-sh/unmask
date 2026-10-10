package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

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
	for _, want := range []string{`id="day-section"`, `class="kpi-grid"`, `data-kpi="requests"`, `data-kpi="serve"`, `data-kpi="pow"`, `data-kpi="captcha"`, `data-kpi="abandon"`, `data-kpi="bans"`, `id="hourly-card"`, `id="comp-card"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Six tiles: the request total, then the five the row has always had.
	if strings.Count(page, `data-kpi="`) != 6 {
		t.Errorf("%d tiles, want 6", strings.Count(page, `data-kpi="`))
	}
	for _, gone := range []string{`table.ai-traffic`, `ai_traffic_card`, `class="ai-tabs"`, `class="pipe"`, `pipe-st`, `pipe-side`} {
		if strings.Contains(page, gone) {
			t.Errorf("page still carries %q", gone)
		}
	}
	// Without the access-log feed the requests tile has no figure: a dash,
	// and the line says the feed is off.
	req := regexp.MustCompile(`(?s)data-kpi="requests">.*?<div class="value">([^<]*)</div>\s*<div class="sub">([^<]*)</div>`).FindStringSubmatch(page)
	if req == nil || strings.TrimSpace(req[1]) != "—" || !strings.Contains(req[2], i18n.T("ja", "overview.kpi.nonhuman_nodata")) {
		t.Errorf("the requests tile must show a dash and say the feed is off: %q", req)
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

// ?partial=recent renders the recent-detections table alone: the rows the
// page redraws every few seconds, without the block's styles and scripts.
func TestOverviewRecentPartial(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/?partial=recent", nil))
	if rr.Code != http.StatusOK || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d cache-control %q", rr.Code, rr.Header().Get("Cache-Control"))
	}
	body := rr.Body.String()
	if !strings.Contains(body, `<table class="events"`) || !strings.Contains(body, `data-events-cap="10"`) {
		t.Errorf("the partial is not the recent table: %.200s", body)
	}
	for _, gone := range []string{`<html`, `<script`, `<style`, `id="day-section"`, `id="recent-card"`, `class="hero`} {
		if strings.Contains(body, gone) {
			t.Errorf("the recent partial carries %q", gone)
		}
	}
	// The page itself carries the card with its live note and the redraw hook.
	rr = httptest.NewRecorder()
	h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil))
	page := rr.Body.String()
	for _, want := range []string{`id="recent-card"`, `id="recent-section"`, `data-src="/unmask/admin/?partial=recent"`, `window.unmaskRefreshRecent = function`, `function unmaskWireEventsTable(root)`, `function wireDt(root)`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}
