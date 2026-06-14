package handlers

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAITrafficDrilldownQuery seeds unmask_crawler_detail_hourly and checks the
// read query windows, groups by category, sums per crawler, and sorts Total
// DESC.
func TestAITrafficDrilldownQuery(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: d}

	nowHour := time.Now().Unix() / 3600
	ins := func(hour int64, cat, crawler string, total, served int) {
		t.Helper()
		if _, err := d.Exec(
			`INSERT INTO unmask_crawler_detail_hourly (bucket_hour, category, crawler, total, served) VALUES (?,?,?,?,?)`,
			hour, cat, crawler, total, served); err != nil {
			t.Fatal(err)
		}
	}
	ins(nowHour, "search-engine", "Googlebot", 100, 10)
	ins(nowHour-1, "search-engine", "Googlebot", 50, 5) // same crawler, earlier hour -> sums
	ins(nowHour, "search-engine", "Bingbot", 30, 0)
	ins(nowHour, "ai-training", "GPTBot", 200, 80)
	ins(nowHour-1000, "search-engine", "OldBot", 999, 0) // outside a 24h window -> excluded

	got := aiTrafficDrilldown(context.Background(), h, 1440) // 24h window

	se := got["search-engine"]
	if len(se) != 2 {
		t.Fatalf("search-engine: want 2 crawlers, got %d (%+v)", len(se), se)
	}
	// Sorted Total DESC: Googlebot (100+50=150) before Bingbot (30).
	if se[0].Crawler != "Googlebot" || se[0].Total != 150 || se[0].Served != 15 || se[0].Passed != 135 {
		t.Errorf("se[0] = %+v, want Googlebot total=150 served=15 passed=135", se[0])
	}
	if se[1].Crawler != "Bingbot" || se[1].Total != 30 || se[1].Passed != 30 {
		t.Errorf("se[1] = %+v, want Bingbot total=30 passed=30", se[1])
	}

	ai := got["ai-training"]
	if len(ai) != 1 || ai[0].Crawler != "GPTBot" || ai[0].Total != 200 || ai[0].Served != 80 {
		t.Errorf("ai-training = %+v, want [GPTBot total=200 served=80]", ai)
	}

	for cat, rows := range got {
		for _, r := range rows {
			if r.Crawler == "OldBot" {
				t.Errorf("OldBot (cat=%s) is outside the 24h window and must be excluded", cat)
			}
		}
	}
}

// TestAITrafficCardDrilldownRender executes the shared ai_traffic_card partial
// with a populated AITrafficDetail map and checks the drill-down store renders
// -- including that semi-trusted crawler names are HTML-escaped, since the
// popover JS lifts this innerHTML verbatim.
func TestAITrafficCardDrilldownRender(t *testing.T) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Lang": i18n.LangEN,
		"AITraffic": []AITrafficRow{
			{Category: "search-engine", Total: 15000, Served: 5000, Passed: 10000},
			{Category: "ai-training", Total: 0, Served: 0, Passed: 0}, // zero-row, no detail
		},
		"AITrafficServed": nil,
		"AITrafficDetail": map[string][]AICrawlerRow{
			"search-engine": {
				{Crawler: "Googlebot", Total: 10000, Served: 3000, Passed: 7000},
				{Crawler: "Bing<bot", Total: 5000, Served: 2000, Passed: 3000}, // hostile name -> must escape
			},
		},
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "ai_traffic_card", data); err != nil {
		t.Fatalf("execute ai_traffic_card: %v", err)
	}
	out := buf.String()

	// The search-engine tag carries the drill-down marker; ai-training (no
	// detail rows) does not.
	if !strings.Contains(out, `data-detail-cat="search-engine"`) {
		t.Error("search-engine tag missing data-detail-cat")
	}
	if strings.Contains(out, `data-detail-cat="ai-training"`) {
		t.Error("ai-training has no detail rows but got a data-detail-cat marker")
	}
	// The per-crawler store renders the crawler names + comma-formatted counts.
	if !strings.Contains(out, "Googlebot") {
		t.Error("drill-down store missing Googlebot")
	}
	if !strings.Contains(out, "10,000") {
		t.Error("drill-down store missing Googlebot's comma-formatted total")
	}
	// Crawler names are semi-trusted (from the embedded crawler list): the
	// hostile "Bing<bot" must be HTML-escaped, since the JS lifts this store's
	// innerHTML into the popover.
	if strings.Contains(out, "Bing<bot") {
		t.Error("crawler name not HTML-escaped (raw < present) -- popover injection risk")
	}
	if !strings.Contains(out, "Bing&lt;bot") {
		t.Error("expected escaped crawler name Bing&lt;bot")
	}
}

// TestAITrafficCardNoDrilldown: a nil AITrafficDetail renders the card with no
// detail store and no tag markers (the drill-down degrades cleanly to absent).
func TestAITrafficCardNoDrilldown(t *testing.T) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Lang":            i18n.LangEN,
		"AITraffic":       []AITrafficRow{{Category: "search-engine", Total: 5, Served: 1, Passed: 4}},
		"AITrafficServed": nil,
		// Typed nil map, mirroring what aiTrafficDrilldown returns with no data
		// (index on a typed nil map yields the zero value; an untyped nil errors).
		"AITrafficDetail": map[string][]AICrawlerRow(nil),
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "ai_traffic_card", data); err != nil {
		t.Fatalf("execute ai_traffic_card: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "ai-detail-store") {
		t.Error("nil AITrafficDetail should not render the detail store")
	}
	if strings.Contains(out, "data-detail-cat") {
		t.Error("nil AITrafficDetail should not mark any tag with data-detail-cat")
	}
}
