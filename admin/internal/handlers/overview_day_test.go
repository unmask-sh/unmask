package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The dashboard's 24-hour section: the composition and the tile row on
// the page, the crawler table back under them (the operator's 2026-10-12 call:
// it is the breakdown of the known-crawler share, and where a search engine
// being challenged shows first), the pipeline stages and the hourly chart
// gone, and the same section alone when the page asks for its refresh.
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
	for _, want := range []string{`id="day-section"`, `class="kpi-grid"`, `data-kpi="requests"`, `data-kpi="serve"`, `data-kpi="pow"`, `data-kpi="captcha"`, `data-kpi="abandon"`, `data-kpi="bans"`, `id="comp-card"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Six tiles: the request total, then the five the row has always had.
	if strings.Count(page, `data-kpi="`) != 6 {
		t.Errorf("%d tiles, want 6", strings.Count(page, `data-kpi="`))
	}
	for _, want := range []string{`data-ai-card`, `class="ai-tabs"`, `id="reasons-card"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, gone := range []string{`class="pipe"`, `pipe-st`, `pipe-side`} {
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
	for _, want := range []string{`class="hero`, `id="comp-card"`, `id="day-refresh"`, `class="js-datetime js-datetime-notz" data-ts="`} {
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

// ?partial=recent on the realtime page renders the recent-detections table
// alone: the rows the page redraws every few seconds, without the block's
// styles and scripts.
func TestLiveRecentPartial(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	rr := httptest.NewRecorder()
	h.AdminLive(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/live/?partial=recent", nil))
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
	h.AdminLive(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/live/", nil))
	page := rr.Body.String()
	for _, want := range []string{`id="recent-card"`, `id="recent-section"`, `data-src="/unmask/admin/live/?partial=recent"`, `window.unmaskRefreshRecent = function`, `function unmaskWireEventsTable(root)`, `function wireDt(root)`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

// The day section does not redraw itself: its figures move by a few per
// minute, and a dashboard that keeps changing under the operator cannot be
// read (2026-10-10).  It redraws on its header's button; the realtime tab
// is the one that moves.
func TestDaySectionHasNoTimer(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/overview.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if strings.Contains(src, "setInterval(") || strings.Contains(src, "setTimeout(unmaskRefreshDay") {
		t.Error("overview.html sets a timer; the day section must redraw only on the button")
	}
	for _, want := range []string{`id="day-refresh"`, "closest('#day-refresh')", "window.unmaskRefreshDay = function"} {
		if !strings.Contains(src, want) {
			t.Errorf("overview.html lacks %q", want)
		}
	}
}

// TestOverviewWeekTab: the dashboard's "1 週間" tab (?range=7d) draws the same
// section over the last seven days -- the tab marked, every text that names
// the window saying seven days, the refresh partial under the same range --
// while the default stays the day.  The line of now is gone from both.
func TestOverviewWeekTab(t *testing.T) {
	h := navHandler(t)
	get := func(target string) string {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.AddCookie(&http.Cookie{Name: "unmask_locale", Value: "ja"})
		rr := httptest.NewRecorder()
		h.AdminTopOverview(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d", target, rr.Code)
		}
		return rr.Body.String()
	}
	day := get("/unmask/admin/")
	week := get("/unmask/admin/?range=7d")
	part := get("/unmask/admin/?range=7d&partial=day")
	for _, page := range []string{day, week, part} {
		if strings.Contains(page, `class="now-line"`) {
			t.Error("the line of now is still drawn")
		}
	}
	if !strings.Contains(day, `href="/unmask/admin/" class="on"`) || strings.Contains(day, `href="/unmask/admin/?range=7d" class="on"`) {
		t.Error("the day page does not mark the day tab alone")
	}
	if !strings.Contains(week, `href="/unmask/admin/?range=7d" class="on"`) || strings.Contains(week, `href="/unmask/admin/" class="on"`) {
		t.Error("the week page does not mark the week tab alone")
	}
	for _, k := range []string{"overview.kpi.range_7d", "overview.kpi.h_7d", "overview.reasons.window_7d", "ai_traffic.window_7d"} {
		want := i18n.T("ja", k)
		if i := strings.Index(want, "<"); i > 0 {
			want = want[:i]
		}
		if !strings.Contains(week, want) || !strings.Contains(part, want) {
			t.Errorf("the week view lacks %s (%q)", k, want)
		}
		if strings.Contains(day, want) {
			t.Errorf("the day view carries the week text %s", k)
		}
	}
	for _, k := range []string{"overview.kpi.range_24h", "overview.kpi.h"} {
		want := i18n.T("ja", k)
		if strings.Contains(week, want) {
			t.Errorf("the week view still says %q", want)
		}
		if !strings.Contains(day, want) {
			t.Errorf("the day view lacks %q", want)
		}
	}
	if !strings.Contains(week, `id="day-refresh"`) {
		t.Error("the week view lacks the refresh button")
	}
}
