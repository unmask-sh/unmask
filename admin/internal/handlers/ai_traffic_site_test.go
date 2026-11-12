package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The crawler card follows the site picker.  With no site picked it reads the
// install-wide tables as it always did; with one picked, the category rows
// and the drill-down under them are that site's rows of the per-site table
// (unmask_crawler_site_hourly, migration 0051), and they add up.

// crawlerHandler is a handler on a migrated database, base path /unmask.
func crawlerHandler(t *testing.T) *Handler {
	t.Helper()
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "c.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: conn}
	var st settings.Settings
	st.Server.BasePath = "/unmask"
	h.SetSettings(st)
	return h
}

// addCrawlerRow writes one row of the per-site crawler table.
func addCrawlerRow(t *testing.T, h *Handler, hour int64, site, category, crawler string, total, served, verified, named int) {
	t.Helper()
	if _, err := h.DB.Exec(`INSERT INTO unmask_crawler_site_hourly
		(bucket_hour, site, category, crawler, total, served, verified, named) VALUES (?,?,?,?,?,?,?,?)`,
		hour, site, category, crawler, total, served, verified, named); err != nil {
		t.Fatal(err)
	}
}

// addInstallWideRow writes one row of the install-wide drill-down table.
func addInstallWideRow(t *testing.T, h *Handler, hour int64, category, crawler string, total, served int) {
	t.Helper()
	if _, err := h.DB.Exec(`INSERT INTO unmask_crawler_detail_hourly
		(bucket_hour, category, crawler, total, served) VALUES (?,?,?,?,?)`,
		hour, category, crawler, total, served); err != nil {
		t.Fatal(err)
	}
}

// seedTwoSites is an install that was upgraded two hours ago.  In the
// current hour Googlebot came to two sites and GPTBot to one: the per-site
// rows, and the install-wide rows that add them up.  Two hours back there is
// an install-wide Googlebot row from before the per-site table existed.  The
// per-minute category counters are given a figure of their own, so a reading
// says which table it came from.
func seedTwoSites(t *testing.T, h *Handler) {
	t.Helper()
	nowHour := time.Now().Unix() / 3600
	addCrawlerRow(t, h, nowHour, "a.example.com", "search-engine", "Googlebot", 100, 10, 80, 0)
	addCrawlerRow(t, h, nowHour, "b.example.com", "search-engine", "Googlebot", 50, 0, 50, 0)
	addCrawlerRow(t, h, nowHour, "a.example.com", "ai-training", "GPTBot", 30, 30, 0, 0)
	addInstallWideRow(t, h, nowHour, "search-engine", "Googlebot", 150, 10)
	addInstallWideRow(t, h, nowHour, "ai-training", "GPTBot", 30, 30)
	addInstallWideRow(t, h, nowHour-2, "search-engine", "Googlebot", 500, 5) // before the per-site rows began
	if _, err := h.DB.Exec(`INSERT INTO unmask_crawler_minute (bucket_min, category, total, served) VALUES (?, 'search-engine', 777, 7)`,
		time.Now().Unix()/60); err != nil {
		t.Fatal(err)
	}
}

func crawlerOf(rows []AICrawlerRow, name string) AICrawlerRow {
	for _, r := range rows {
		if r.Crawler == name {
			return r
		}
	}
	return AICrawlerRow{}
}

func categoryOf(rows []AITrafficRow, name string) AITrafficRow {
	for _, r := range rows {
		if r.Category == name {
			return r
		}
	}
	return AITrafficRow{}
}

func TestAITrafficDrilldownFollowsTheSite(t *testing.T) {
	h := crawlerHandler(t)
	seedTwoSites(t, h)
	ctx := context.Background()

	// No site picked ("" and the "default" sentinel alike): the install-wide
	// rows, the ones from before the per-site table among them.
	for _, site := range []string{"", "default"} {
		got := aiTrafficDrilldown(ctx, h, 1440, site)
		if g := crawlerOf(got["search-engine"], "Googlebot"); g.Total != 650 || g.Served != 15 || g.Passed != 635 {
			t.Errorf("site %q: Googlebot = %+v, want total 650 served 15 passed 635", site, g)
		}
		if g := crawlerOf(got["ai-training"], "GPTBot"); g.Total != 30 || g.Served != 30 {
			t.Errorf("site %q: GPTBot = %+v, want total 30 served 30", site, g)
		}
	}

	// A site: its rows only.
	a := aiTrafficDrilldown(ctx, h, 1440, "a.example.com")
	if g := crawlerOf(a["search-engine"], "Googlebot"); g.Total != 100 || g.Served != 10 || g.Passed != 90 {
		t.Errorf("a.example.com: Googlebot = %+v, want total 100 served 10 passed 90", g)
	}
	if g := crawlerOf(a["ai-training"], "GPTBot"); g.Total != 30 {
		t.Errorf("a.example.com: GPTBot = %+v, want total 30", g)
	}
	b := aiTrafficDrilldown(ctx, h, 1440, "b.example.com")
	if g := crawlerOf(b["search-engine"], "Googlebot"); g.Total != 50 || g.Served != 0 {
		t.Errorf("b.example.com: Googlebot = %+v, want total 50 served 0", g)
	}
	if len(b["ai-training"]) != 0 {
		t.Errorf("b.example.com: ai-training = %+v, want none (GPTBot came to the other site)", b["ai-training"])
	}
	if got := aiTrafficDrilldown(ctx, h, 1440, "nobody.example.com"); len(got) != 0 {
		t.Errorf("a site with no crawler rows: %+v, want nothing", got)
	}
}

// With no site picked neither reading touches the per-site table: the card
// costs what it did before that table existed, however many sites and rows
// it holds.
func TestAITrafficAllSitesReadsOnlyTheInstallWideTables(t *testing.T) {
	h := crawlerHandler(t)
	seedTwoSites(t, h)
	if _, err := h.DB.Exec(`DROP TABLE unmask_crawler_site_hourly`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if g := crawlerOf(aiTrafficDrilldown(ctx, h, 1440, "")["search-engine"], "Googlebot"); g.Total != 650 {
		t.Errorf("drill-down without the per-site table: Googlebot = %+v, want total 650", g)
	}
	if g := categoryOf(aiTrafficSummary(ctx, h, 1440, ""), "search-engine"); g.Total != 777 {
		t.Errorf("categories without the per-site table: search-engine = %+v, want total 777", g)
	}
}

func TestAITrafficSummaryFollowsTheSite(t *testing.T) {
	h := crawlerHandler(t)
	seedTwoSites(t, h)
	ctx := context.Background()

	// No site picked: the install-wide per-minute counters, as before.
	for _, site := range []string{"", "default"} {
		all := aiTrafficSummary(ctx, h, 1440, site)
		if g := categoryOf(all, "search-engine"); g.Total != 777 || g.Served != 7 || g.Passed != 770 {
			t.Errorf("site %q: search-engine = %+v, want the per-minute table's 777 / 7 / 770", site, g)
		}
	}

	// A site: the categories summed from its per-site rows.
	a := aiTrafficSummary(ctx, h, 1440, "a.example.com")
	if g := categoryOf(a, "search-engine"); g.Total != 100 || g.Served != 10 || g.Passed != 90 {
		t.Errorf("a.example.com: search-engine = %+v, want 100 / 10 / 90", g)
	}
	if g := categoryOf(a, "ai-training"); g.Total != 30 || g.Served != 30 || g.Passed != 0 {
		t.Errorf("a.example.com: ai-training = %+v, want 30 / 30 / 0", g)
	}
	// Every category is a row, the ones with nothing at zero and below the
	// ones with something.
	for name, rows := range map[string][]AITrafficRow{
		"a.example.com":      a,
		"nobody.example.com": aiTrafficSummary(ctx, h, 1440, "nobody.example.com"),
	} {
		if len(rows) != len(classify.CrawlerTagOrder) {
			t.Fatalf("%s: %d category rows, want every category (%d)", name, len(rows), len(classify.CrawlerTagOrder))
		}
		for i := 1; i < len(rows); i++ {
			if rows[i-1].Total < rows[i].Total {
				t.Errorf("%s: rows not by total: %d before %d", name, rows[i-1].Total, rows[i].Total)
			}
		}
	}
	if a[0].Category != "search-engine" || a[1].Category != "ai-training" || a[2].Total != 0 {
		t.Errorf("a.example.com: order = %s, %s, then total %d; want search-engine, ai-training, then zeros", a[0].Category, a[1].Category, a[2].Total)
	}
}

// With a site picked a category row and the crawlers under it are read from
// the same rows with the same lower bound -- the hour that holds the window's
// first instant -- so the popover adds up to the row it opens from.
func TestAITrafficSiteSummaryMatchesItsDrilldown(t *testing.T) {
	h := crawlerHandler(t)
	nowHour := time.Now().Unix() / 3600
	addCrawlerRow(t, h, nowHour, "a.example.com", "search-engine", "Googlebot", 7, 1, 0, 0)
	addCrawlerRow(t, h, nowHour-1, "a.example.com", "search-engine", "Googlebot", 20, 2, 0, 0) // the hour the window starts in
	addCrawlerRow(t, h, nowHour-1, "a.example.com", "search-engine", "bingbot", 5, 0, 0, 0)
	addCrawlerRow(t, h, nowHour-2, "a.example.com", "search-engine", "Googlebot", 900, 9, 0, 0) // before it
	ctx := context.Background()
	const minutes = 60

	row := categoryOf(aiTrafficSummary(ctx, h, minutes, "a.example.com"), "search-engine")
	if row.Total != 32 || row.Served != 3 {
		t.Errorf("category row = %+v, want total 32 served 3 (the window's two hours)", row)
	}
	sumTotal, sumServed := 0, 0
	for _, c := range aiTrafficDrilldown(ctx, h, minutes, "a.example.com")["search-engine"] {
		sumTotal += c.Total
		sumServed += c.Served
	}
	if sumTotal != row.Total || sumServed != row.Served {
		t.Errorf("the drill-down adds up to %d / %d, the category row says %d / %d", sumTotal, sumServed, row.Total, row.Served)
	}
}

// The note under a site's table: shown while the window reaches back to
// install-wide rows older than the per-site table's first hour, which no
// site's figures include.
func TestAITrafficPreSplit(t *testing.T) {
	ctx := context.Background()
	nowHour := time.Now().Unix() / 3600

	// An install upgraded two hours ago.
	h := crawlerHandler(t)
	seedTwoSites(t, h)
	for _, c := range []struct {
		name    string
		minutes int
		site    string
		want    bool
	}{
		{"a site, the day", 1440, "a.example.com", true},
		{"a site with no rows of its own", 1440, "nobody.example.com", true},
		{"no site picked", 1440, "", false},
		{"the default sentinel", 1440, "default", false},
		{"a site, a window that begins after the older rows", 30, "a.example.com", false},
	} {
		if got := aiTrafficPreSplit(ctx, h, c.minutes, c.site); got != c.want {
			t.Errorf("upgraded install, %s: %v, want %v", c.name, got, c.want)
		}
	}

	// Just upgraded: no per-site row yet, so every install-wide row in the
	// window is from before.
	h = crawlerHandler(t)
	addInstallWideRow(t, h, nowHour-3, "search-engine", "Googlebot", 500, 5)
	if !aiTrafficPreSplit(ctx, h, 1440, "a.example.com") {
		t.Error("no per-site row yet, an install-wide row in the window: the note is not shown")
	}
	if aiTrafficPreSplit(ctx, h, 60, "a.example.com") {
		t.Error("no per-site row yet, no install-wide row in the window: the note is shown")
	}

	// A new install: the two tables begin in the same hour, and stay
	// together from there on.
	h = crawlerHandler(t)
	for _, hour := range []int64{nowHour - 5, nowHour} {
		addInstallWideRow(t, h, hour, "search-engine", "Googlebot", 10, 0)
		addCrawlerRow(t, h, hour, "a.example.com", "search-engine", "Googlebot", 10, 0, 0, 0)
	}
	if aiTrafficPreSplit(ctx, h, 1440, "a.example.com") {
		t.Error("a new install: the note is shown")
	}
	// Nothing counted at all.
	if aiTrafficPreSplit(ctx, crawlerHandler(t), 1440, "a.example.com") {
		t.Error("empty tables: the note is shown")
	}

	// Best-effort: no database, or a read that fails, is no note.
	if aiTrafficPreSplit(ctx, &Handler{}, 1440, "a.example.com") {
		t.Error("no database: the note is shown")
	}
	h = crawlerHandler(t)
	seedTwoSites(t, h)
	if _, err := h.DB.Exec(`DROP TABLE unmask_crawler_site_hourly`); err != nil {
		t.Fatal(err)
	}
	if aiTrafficPreSplit(ctx, h, 1440, "a.example.com") {
		t.Error("a read that fails: the note is shown")
	}
}

// crawlerPage renders a page with the site picker's cookie set (or not).
func crawlerPage(t *testing.T, fn http.HandlerFunc, target, site, role string) string {
	t.Helper()
	req := asRole(httptest.NewRequest(http.MethodGet, target, nil), role)
	req.Header.Set("Accept-Language", "en")
	if site != "" {
		req.AddCookie(&http.Cookie{Name: "unmask_site", Value: site})
	}
	req.SetPathValue("site", "default")
	rr := httptest.NewRecorder()
	fn(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: status %d", target, rr.Code)
	}
	return rr.Body.String()
}

// crawlerCard cuts the crawler card out of a page.
func crawlerCard(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, `<div class="bcd-card ai-traffic-card" data-ai-card>`)
	if i < 0 {
		t.Fatal("the crawler card is not on the page")
	}
	j := strings.Index(body[i:], `<div class="ai-pane" data-pane="served"`)
	if j < 0 {
		t.Fatal("the crawler card has no challenged pane")
	}
	return body[i : i+j]
}

// TestCrawlerCardOnThePagesFollowsTheSite: the dashboard (the page and the
// day section its refresh redraws) and the statistics page hand the picker's
// site to the card -- the site's own figures, and the note about what was
// counted before the per-site rows began; with no site picked, the
// install-wide figures and no note.
func TestCrawlerCardOnThePagesFollowsTheSite(t *testing.T) {
	h := crawlerHandler(t)
	seedTwoSites(t, h)
	const note = "This period includes counts from before per-site counting began."
	for name, page := range map[string]struct {
		fn     http.HandlerFunc
		target string
	}{
		"dashboard":             {h.AdminTopOverview, "/unmask/admin/"},
		"dashboard day section": {h.AdminTopOverview, "/unmask/admin/?partial=day"},
		"statistics":            {h.AdminStats, "/unmask/admin/stats/default/?range=24h"},
	} {
		site := crawlerCard(t, crawlerPage(t, page.fn, page.target, "a.example.com", user.RoleViewer))
		// search-engine on a.example.com: 100 requests, 10 challenged, 90 passed.
		if !strings.Contains(site, `<td class="bcd-num">100</td>`) || !strings.Contains(site, `<td class="bcd-num">90</td>`) {
			t.Errorf("%s, a site picked: the card does not show the site's search-engine row (100 / 10 / 90)", name)
		}
		if strings.Contains(site, "777") || strings.Contains(site, "650") {
			t.Errorf("%s, a site picked: the card shows an all-sites figure", name)
		}
		if !strings.Contains(site, note) {
			t.Errorf("%s, a site picked: no note about the counts from before the per-site rows began", name)
		}
		all := crawlerCard(t, crawlerPage(t, page.fn, page.target, "", user.RoleViewer))
		if !strings.Contains(all, `<td class="bcd-num">777</td>`) {
			t.Errorf("%s, no site picked: the card does not show the install-wide search-engine row (777)", name)
		}
		if strings.Contains(all, note) {
			t.Errorf("%s, no site picked: the note is shown", name)
		}
	}
}
