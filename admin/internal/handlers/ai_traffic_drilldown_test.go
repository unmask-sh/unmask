package handlers

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
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

// TestAITrafficDrilldownRangeVerified checks the RangeVerified flag: a crawler
// whose vendor publishes IP ranges is marked ONLY when every backing preset is
// enabled (so its genuine bots are bypassed and its "served" is all spoof),
// while a vendor with no published range is never marked.
func TestAITrafficDrilldownRangeVerified(t *testing.T) {
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
	ins := func(cat, crawler string, total, served int) {
		if _, err := d.Exec(
			`INSERT INTO unmask_crawler_detail_hourly (bucket_hour, category, crawler, total, served) VALUES (?,?,?,?,?)`,
			nowHour, cat, crawler, total, served); err != nil {
			t.Fatal(err)
		}
	}
	ins("search-engine", "Googlebot", 34119, 34112) // range vendor
	ins("search-engine", "bingbot", 7356, 0)        // range vendor
	ins("search-engine", "Yeti", 427, 50)           // NO published range

	rvOf := func() map[string]bool {
		got := aiTrafficDrilldown(context.Background(), h, 1440)
		out := map[string]bool{}
		for _, r := range got["search-engine"] {
			out[r.Crawler] = r.RangeVerified
		}
		return out
	}

	// No presets enabled -> nothing is range-verified (UA-only rescue), so a
	// crawler's served could still be genuine: never claim it as spoof.
	h.SetSettings(settings.Settings{})
	if rv := rvOf(); rv["Googlebot"] || rv["bingbot"] || rv["Yeti"] {
		t.Errorf("presets off: nothing should be range-verified, got %+v", rv)
	}

	// Google's three range presets + bing enabled, past the seen-version gate.
	h.SetSettings(settings.Settings{Nginx: settings.Nginx{
		SeenVersion:            "v0.1.7",
		BypassIPEnabledPresets: []string{"google-common", "google-special", "google-user-triggered", "bing"},
	}})
	rv := rvOf()
	if !rv["Googlebot"] {
		t.Error("Googlebot should be range-verified when all google presets are on")
	}
	if !rv["bingbot"] {
		t.Error("bingbot should be range-verified when the bing preset is on")
	}
	if rv["Yeti"] {
		t.Error("Yeti has no published range and must never be range-verified")
	}

	// A partial Google set (one preset missing) reverts Google to UA-only.
	h.SetSettings(settings.Settings{Nginx: settings.Nginx{
		SeenVersion:            "v0.1.7",
		BypassIPEnabledPresets: []string{"google-common", "bing"},
	}})
	rv = rvOf()
	if rv["Googlebot"] {
		t.Error("Googlebot must NOT be range-verified when only part of its preset set is on")
	}
	if !rv["bingbot"] {
		t.Error("bingbot should stay range-verified (its single preset is still on)")
	}
}

// TestSparkPoints checks the sparkline polyline generator: degenerate series
// draw nothing, and a ramp rises (its last/peak point sits higher on screen =
// a smaller y than the first).
func TestSparkPoints(t *testing.T) {
	for _, s := range [][]int{nil, {5}, {0, 0, 0}} {
		if got := sparkPoints(s); got != "" {
			t.Errorf("sparkPoints(%v) = %q, want empty", s, got)
		}
	}
	pts := sparkPoints([]int{0, 0, 5, 10})
	coords := strings.Fields(pts)
	if len(coords) != 4 {
		t.Fatalf("sparkPoints ramp = %q (%d points), want 4", pts, len(coords))
	}
	yOf := func(c string) float64 {
		var x, y float64
		fmt.Sscanf(c, "%f,%f", &x, &y)
		return y
	}
	first, last := yOf(coords[0]), yOf(coords[len(coords)-1])
	if last >= first {
		t.Errorf("ramp: last y=%.1f should be above (smaller than) first y=%.1f", last, first)
	}
	if last > 2 { // peak normalised to the top of the 1px-inset box
		t.Errorf("ramp peak y=%.1f, want near the top", last)
	}
}

// TestAITrafficDrilldownSparkline seeds a crawler ramping over several hours and
// checks the drill-down attaches a non-empty sparkline plus the summed total.
func TestAITrafficDrilldownSparkline(t *testing.T) {
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
	ramp := []int{2, 5, 9, 20, 50} // last 5 hours, rising
	for i, v := range ramp {
		hour := nowHour - int64(len(ramp)-1-i)
		if _, err := d.Exec(
			`INSERT INTO unmask_crawler_detail_hourly (bucket_hour, category, crawler, total, served) VALUES (?,?,?,?,?)`,
			hour, "ai-training", "ClaudeBot", v, 0); err != nil {
			t.Fatal(err)
		}
	}
	got := aiTrafficDrilldown(context.Background(), h, 24*60) // 24h window
	rows := got["ai-training"]
	if len(rows) != 1 || rows[0].Crawler != "ClaudeBot" {
		t.Fatalf("want one ClaudeBot row, got %+v", rows)
	}
	if rows[0].Total != 86 { // 2+5+9+20+50
		t.Errorf("total=%d, want 86", rows[0].Total)
	}
	if rows[0].Spark == "" {
		t.Error("ramping crawler should have a non-empty sparkline")
	}
}

// TestPruneCrawlerDetailHourly checks the retention cut: rows past keepDays go,
// rows inside stay, and keepDays<=0 is a no-op (keep forever).
func TestPruneCrawlerDetailHourly(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	nowHour := time.Now().Unix() / 3600
	ins := func(hoursAgo int64, name string) {
		if _, err := d.Exec(
			`INSERT INTO unmask_crawler_detail_hourly (bucket_hour, category, crawler, total, served) VALUES (?,?,?,?,?)`,
			nowHour-hoursAgo, "ai-training", name, 10, 0); err != nil {
			t.Fatal(err)
		}
	}
	ins(1, "recent")       // 1h ago
	ins(24*5, "five-days") // 5d ago
	ins(24*100, "old")     // 100d ago

	n, err := dashboard.PruneCrawlerDetailHourly(context.Background(), d, 90)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned %d rows, want 1 (the 100-day row)", n)
	}
	var cnt int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_crawler_detail_hourly`).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 2 {
		t.Errorf("remaining=%d, want 2 (recent + five-days)", cnt)
	}
	if n2, _ := dashboard.PruneCrawlerDetailHourly(context.Background(), d, 0); n2 != 0 {
		t.Errorf("keepDays=0 pruned %d, want 0 (keep forever)", n2)
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
				{Crawler: "Googlebot", Total: 10000, Served: 3000, Passed: 7000, Spark: "1.0,15.0 32.0,8.0 63.0,1.0"},
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
	// a row with a Spark renders the sparkline SVG with its points intact.
	if !strings.Contains(out, `<svg class="ai-spark"`) {
		t.Error("expected an ai-spark sparkline svg for the row carrying Spark")
	}
	if !strings.Contains(out, `points="1.0,15.0 32.0,8.0 63.0,1.0"`) {
		t.Error("sparkline polyline points missing or altered")
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
