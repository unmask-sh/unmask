package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The dashboard's day section carries the crawler card again (who the known
// crawlers were, and whether a search engine was challenged) and, in place of
// the ten latest detections, the day's detections by reason.  Both sit inside
// the section the refresh button redraws, so both have to come back with it.
func TestOverviewShowsCrawlersAndReasons(t *testing.T) {
	dashboard.ResetHourlyAggReadyForTest()
	defer dashboard.ResetHourlyAggReadyForTest()
	h := newTestHandler(t)
	if err := db.Migrate(h.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	add := func(i int, phase, payload string) {
		t.Helper()
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site, host, ip_address, phase, flags, reload_count, payload_json, date_created)
			VALUES ('s', 'h', ?, ?, 0, 0, ?, ?)`, []byte{10, 0, 1, byte(i)}, phase, payload, now); err != nil {
			t.Fatal(err)
		}
	}
	for i, fr := range []string{"ja4_bot", "ja4_bot", "ja4_bot", "custom_rule", "none"} {
		add(i, "serve", `{"force_reason":"`+fr+`"}`)
	}
	add(9, "load", `{"force_reason":"ja4_bot"}`) // not a serve: never counted
	if _, err := h.DB.Exec(`INSERT INTO unmask_crawler_minute (bucket_min, category, total, served) VALUES (?, 'search-engine', 40, 2)`,
		time.Now().Unix()/60); err != nil {
		t.Fatal(err)
	}

	body := renderOverview(t, h)
	day := between(t, body, `<div id="day-section">`, `<p class="day-err"`)
	if !strings.Contains(day, `data-ai-card`) || !strings.Contains(day, `ai-cat-search-engine`) {
		t.Error("the crawler card is not in the day section")
	}
	if !strings.Contains(day, `id="reasons-card"`) {
		t.Fatal("the detections-by-reason card is not in the day section")
	}

	// Rows by count, ties in the card's order; every known reason present,
	// the zeros marked so the toggle can fold them.
	rows := regexp.MustCompile(`<tr data-reason="([a-z0-9_]+)"( class="muted-row")?>`).FindAllStringSubmatch(day, -1)
	if len(rows) != len(overviewReasonOrder) {
		t.Fatalf("got %d reason rows, want every known reason (%d)", len(rows), len(overviewReasonOrder))
	}
	for i, want := range []string{"ja4_bot", "custom_rule", "none"} {
		if rows[i][1] != want || rows[i][2] != "" {
			t.Errorf("row %d = %q (muted=%v), want %q unmuted", i, rows[i][1], rows[i][2] != "", want)
		}
	}
	for _, r := range rows[3:] {
		if r[2] == "" {
			t.Errorf("reason %q has no events but is not marked muted", r[1])
		}
	}
	base := h.cfg().Server.BasePath
	if !strings.Contains(day, `href="`+base+`/admin/hunt/?range=24h&amp;force_reason=ja4_bot"`) {
		t.Error("a reason does not open bot hunt filtered on it over the day")
	}
	if !regexp.MustCompile(`(?s)data-reason="ja4_bot".*?<td class="bcd-num">3</td>.*?60\.0%`).MatchString(day) {
		t.Error("ja4_bot's row should carry its count and its share of the card")
	}
	// The gear opens where the reason is set; a reason with nowhere to
	// point keeps the cell, empty, so the columns stay aligned.
	if !regexp.MustCompile(`(?s)data-reason="ja4_bot".*?<td class="rs-set"><a href="` + base + `/admin/settings/ja4-verdicts/" aria-label="[^"]+">`).MatchString(day) {
		t.Error("ja4_bot's row does not open the JA4 verdict settings")
	}
	if !regexp.MustCompile(`(?s)data-reason="axis_deny".*?<td class="rs-set"></td>`).MatchString(day) {
		t.Error("axis_deny names no axis, so its row should have no settings link")
	}

	// The refresh redraws the section from ?partial=day: both cards come back,
	// and their page-level script and style do not come back a second time.
	part := renderOverviewQuery(t, h, "?partial=day")
	for _, want := range []string{`data-ai-card`, `id="reasons-card"`} {
		if !strings.Contains(part, want) {
			t.Errorf("the redrawn section lost %s", want)
		}
	}
	for _, once := range []string{"window.unmaskWireAITraffic = function", "window.unmaskZeroRows = function"} {
		if n := strings.Count(body, once); n != 1 {
			t.Errorf("%q appears %d times on the page, want 1", once, n)
		}
		if strings.Contains(part, once) {
			t.Errorf("the redrawn section carries %q again", once)
		}
	}
	// ...and the redraw wires the new markup.
	for _, call := range []string{"unmaskWireAITraffic(day)", "unmaskZeroRows(day)"} {
		if !strings.Contains(body, call) {
			t.Errorf("the refresh does not call %s", call)
		}
	}
}

// Every reason the card links to has to be one bot hunt's filter offers, or
// the page it opens shows the filter as "all reasons" while it is not.
func TestHuntOffersEveryDashboardReason(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range overviewReasonOrder {
		if !strings.Contains(string(b), `<option value="`+r+`"`) {
			t.Errorf("bot hunt's reason filter has no %q option", r)
		}
	}
}

// Every reason's settings link has to land: on a tab that exists, on the card
// it names, under a title both languages have.  A tab renamed or a card's id
// dropped would otherwise leave the gear opening a 404 or the top of a long
// tab, which nothing else would notice.
func TestReasonSettingsLinksLand(t *testing.T) {
	h := newTestHandler(t)
	known := make(map[string]bool, len(overviewReasonOrder))
	for _, r := range overviewReasonOrder {
		known[r] = true
		if _, ok := overviewReasonSettings[r]; !ok && r != "axis_deny" {
			t.Errorf("reason %q has no settings link", r)
		}
	}
	for r, s := range overviewReasonSettings {
		if !known[r] {
			t.Errorf("settings link for %q, which the card never lists", r)
		}
		for _, lang := range []i18n.Lang{i18n.LangJA, i18n.LangEN} {
			if i18n.T(lang, s.name) == s.name {
				t.Errorf("reason %q: %q has no %s title", r, s.name, lang)
			}
		}
		path, frag, _ := strings.Cut(s.path, "#")
		tab, ok := strings.CutPrefix(path, "settings/")
		if !ok {
			if path != "bans/" {
				t.Errorf("reason %q opens %q, neither a settings tab nor the ban list", r, path)
			}
			continue
		}
		tab = strings.TrimSuffix(tab, "/")
		if !settingsTabs[tab] {
			t.Errorf("reason %q opens settings tab %q, which does not exist", r, tab)
			continue
		}
		if frag != "" && !strings.Contains(renderSettingsTab(t, h, tab), `id="`+frag+`"`) {
			t.Errorf("reason %q opens #%s, which the %s tab does not have", r, frag, tab)
		}
	}
}

func between(t *testing.T, s, from, to string) string {
	t.Helper()
	i := strings.Index(s, from)
	j := strings.Index(s, to)
	if i < 0 || j < 0 || j < i {
		t.Fatalf("cannot find %q .. %q", from, to)
	}
	return s[i:j]
}

func renderOverviewQuery(t *testing.T, h *Handler, q string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/"+q, nil)
	r.AddCookie(issueSessionCookie(h.cfg().Secret.BVSecret, 1, "superadmin", false, false))
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("overview%s status %d", q, rr.Code)
	}
	return rr.Body.String()
}
