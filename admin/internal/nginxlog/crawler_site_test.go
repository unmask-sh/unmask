package nginxlog

import (
	"fmt"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// Beside the install-wide drill-down the reader keeps the same counts per
// site (unmask_crawler_site_hourly, migration 0051): the same crawler on two
// hosts is two rows there, each with what that host received, and each row
// also says how many of its requests came from the vendor's own ranges and
// how many went through on the name alone.  The install-wide table is
// written as it always was.

const (
	googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	browserUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0 Safari/537.36"
)

// crawlerSiteReader is a Reader on a migrated database that knows one
// crawler, Googlebot, in the search-engine category.
func crawlerSiteReader(t *testing.T) (*Reader, *db.DB) {
	t.Helper()
	d := handoverDB(t)
	r := Start("", d)
	t.Cleanup(r.Close)
	r.SetCrawlerClassifier(func(ua string) string {
		if strings.Contains(ua, "Googlebot") {
			return "search-engine"
		}
		return ""
	})
	r.SetCrawlerNamer(func(ua, tag string) string { return "Googlebot" })
	return r, d
}

// crawlerLine is one access-log line: fc and sb as the configuration logs
// them (challenged / passed on the name), the rest fixed.
func crawlerLine(site, ip string, fc, sb int, ua string) string {
	return fmt.Sprintf("1751400000.1 site=%s kind= fc=%d hp=0 ip=%s ja4=- hpuri=- bp=0 scheme=https cr=- rv=0123456789ab pv=0 sb=%d ua=%s",
		site, fc, ip, sb, ua)
}

type crawlerSiteRow struct{ total, served, verified, named int }

// crawlerSiteRows reads the per-site table, keyed by "site/crawler".
func crawlerSiteRows(t *testing.T, d *db.DB) map[string]crawlerSiteRow {
	t.Helper()
	rows, err := d.Query(`SELECT site, crawler, total, served, verified, named FROM unmask_crawler_site_hourly`)
	if err != nil {
		t.Fatalf("read unmask_crawler_site_hourly: %v", err)
	}
	defer rows.Close()
	out := map[string]crawlerSiteRow{}
	for rows.Next() {
		var site, crawler string
		var v crawlerSiteRow
		if err := rows.Scan(&site, &crawler, &v.total, &v.served, &v.verified, &v.named); err != nil {
			t.Fatal(err)
		}
		out[site+"/"+crawler] = v
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// crawlerDetailTotals reads the install-wide drill-down: how many rows it
// holds for the crawler, and their total and served.
func crawlerDetailTotals(t *testing.T, d *db.DB, crawler string) (n, total, served int) {
	t.Helper()
	if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(total), 0), COALESCE(SUM(served), 0)
		FROM unmask_crawler_detail_hourly WHERE crawler = ?`, crawler).Scan(&n, &total, &served); err != nil {
		t.Fatalf("read unmask_crawler_detail_hourly: %v", err)
	}
	return n, total, served
}

func wantSiteRows(t *testing.T, got, want map[string]crawlerSiteRow) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("per-site rows = %v, want %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %+v, want %+v", k, got[k], w)
		}
	}
}

// Two hosts, one crawler: two per-site rows, each with its own host's
// requests.  The install-wide drill-down and the per-minute category
// counters beside them are one row each, the two hosts together, as before.
func TestCrawlerSiteRowsAreKeptPerSite(t *testing.T) {
	r, d := crawlerSiteReader(t)
	r.onLine(crawlerLine("a.example.com", "192.0.2.10", 0, 0, googlebotUA))
	r.onLine(crawlerLine("a.example.com", "192.0.2.10", 0, 0, googlebotUA))
	r.onLine(crawlerLine("a.example.com", "192.0.2.11", 1, 0, googlebotUA)) // challenged
	r.onLine(crawlerLine("b.example.com", "192.0.2.10", 0, 0, googlebotUA))
	r.onLine(crawlerLine("b.example.com", "192.0.2.12", 0, 0, browserUA)) // not a crawler
	r.flushOnce(true)

	wantSiteRows(t, crawlerSiteRows(t, d), map[string]crawlerSiteRow{
		"a.example.com/Googlebot": {total: 3, served: 1},
		"b.example.com/Googlebot": {total: 1},
	})
	if n, total, served := crawlerDetailTotals(t, d, "Googlebot"); n != 1 || total != 4 || served != 1 {
		t.Errorf("unmask_crawler_detail_hourly: %d row(s), total %d, served %d; want 1 row, 4, 1", n, total, served)
	}
	var n, total, served int
	if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(total), 0), COALESCE(SUM(served), 0)
		FROM unmask_crawler_minute WHERE category = 'search-engine'`).Scan(&n, &total, &served); err != nil {
		t.Fatal(err)
	}
	if n != 1 || total != 4 || served != 1 {
		t.Errorf("unmask_crawler_minute: %d row(s), total %d, served %d; want 1 row, 4, 1", n, total, served)
	}
}

// A request whose address is inside the vendor's ranges counts as verified; a
// request the configuration passed on the name alone counts as named -- the
// same requests unmask_crawler_named_hourly counts.  A line with no address
// is not asked about.
func TestCrawlerSiteRowsCountVerifiedAndNamed(t *testing.T) {
	r, d := crawlerSiteReader(t)
	var asked []string
	r.SetCrawlerRangeCheck(func(name, ip string) bool {
		asked = append(asked, name+"@"+ip)
		return name == "Googlebot" && ip == "192.0.2.10"
	})
	r.onLine(crawlerLine("a.example.com", "192.0.2.10", 0, 0, googlebotUA))   // in range, passed
	r.onLine(crawlerLine("a.example.com", "192.0.2.10", 1, 0, googlebotUA))   // in range, challenged all the same
	r.onLine(crawlerLine("a.example.com", "198.51.100.7", 0, 1, googlebotUA)) // elsewhere, passed on the name
	r.onLine(crawlerLine("a.example.com", "198.51.100.7", 0, 1, googlebotUA))
	r.onLine(crawlerLine("a.example.com", "198.51.100.8", 1, 1, googlebotUA)) // named, but challenged: not a pass
	// A line from a configuration that logs no address.
	r.onLine("1751400000.2 site=a.example.com kind= fc=0 hp=0 ua=" + googlebotUA)
	r.flushOnce(true)

	got := crawlerSiteRows(t, d)["a.example.com/Googlebot"]
	if want := (crawlerSiteRow{total: 6, served: 2, verified: 2, named: 2}); got != want {
		t.Errorf("per-site row = %+v, want %+v", got, want)
	}
	if len(asked) != 5 {
		t.Errorf("the range check was asked %d times (%v), want once per line that carries an address", len(asked), asked)
	}
	var claimed int
	if err := d.QueryRow(`SELECT COALESCE(SUM(cnt), 0) FROM unmask_crawler_named_hourly WHERE crawler = 'Googlebot'`).Scan(&claimed); err != nil {
		t.Fatal(err)
	}
	if claimed != got.named {
		t.Errorf("unmask_crawler_named_hourly counts %d, the per-site row's named %d: the two count the same requests", claimed, got.named)
	}
}

// Without a range check nothing counts as verified, and nothing breaks.
func TestCrawlerSiteRowsWithoutARangeCheck(t *testing.T) {
	r, d := crawlerSiteReader(t)
	r.onLine(crawlerLine("a.example.com", "192.0.2.10", 0, 0, googlebotUA))
	r.flushOnce(true)
	if got, want := crawlerSiteRows(t, d)["a.example.com/Googlebot"], (crawlerSiteRow{total: 1}); got != want {
		t.Errorf("per-site row = %+v, want %+v", got, want)
	}
}

// Forward-auth has no access-log line: /api/check hands the site and the
// client address over itself, and the rows come out as the log's would.
func TestForwardAuthBumpCrawlerCarriesSiteAndAddress(t *testing.T) {
	r, d := crawlerSiteReader(t)
	r.SetCrawlerRangeCheck(func(name, ip string) bool { return ip == "192.0.2.10" })
	r.BumpCrawler("shop.example.com", googlebotUA, "192.0.2.10", false)
	r.BumpCrawler("shop.example.com", googlebotUA, "198.51.100.7", true)
	r.BumpCrawler("blog.example.com", googlebotUA, "198.51.100.7", false)
	r.BumpCrawler("blog.example.com", browserUA, "198.51.100.9", false) // not a crawler
	r.BumpCrawler("", googlebotUA, "", false)                           // no host, no address
	r.flushOnce(true)

	wantSiteRows(t, crawlerSiteRows(t, d), map[string]crawlerSiteRow{
		"shop.example.com/Googlebot": {total: 2, served: 1, verified: 1},
		"blog.example.com/Googlebot": {total: 1},
		"default/Googlebot":          {total: 1}, // a request without a host, as the log's is filed
	})
	if n, total, served := crawlerDetailTotals(t, d, "Googlebot"); n != 1 || total != 4 || served != 1 {
		t.Errorf("unmask_crawler_detail_hourly: %d row(s), total %d, served %d; want 1 row, 4, 1", n, total, served)
	}
}

// The Host header names the site on the forward-auth path too, so its site
// is bounded as a logged Host is: off the defined list it is filed under
// OtherSite, and past the cap of distinct sites in a minute likewise.  Only
// a crawler's request counts against that cap.
func TestForwardAuthBumpCrawlerBoundsTheSite(t *testing.T) {
	t.Run("a host off the defined list", func(t *testing.T) {
		r, d := crawlerSiteReader(t)
		r.SetSiteCheck(func(site string) bool { return site == "shop.example.com" })
		r.BumpCrawler("shop.example.com", googlebotUA, "192.0.2.10", false)
		r.BumpCrawler("made-up-1.example", googlebotUA, "192.0.2.10", false)
		r.BumpCrawler("made-up-2.example", googlebotUA, "192.0.2.10", false)
		r.flushOnce(true)
		got := crawlerSiteRows(t, d)
		if len(got) != 2 || got["shop.example.com/Googlebot"].total != 1 || got[OtherSite+"/Googlebot"].total != 2 {
			t.Errorf("per-site rows = %v, want shop.example.com with 1 and %s with 2", got, OtherSite)
		}
	})
	t.Run("more hosts in a minute than the cap", func(t *testing.T) {
		clearOfMinuteBoundary(t)
		r, d := crawlerSiteReader(t)
		// A browser varying its Host mints nothing and uses up nothing.
		for i := 0; i < siteCapPerMinute+10; i++ {
			r.BumpCrawler(fmt.Sprintf("b%d.example", i), browserUA, "192.0.2.20", false)
		}
		const over = 7
		for i := 0; i < siteCapPerMinute+over; i++ {
			r.BumpCrawler(fmt.Sprintf("h%d.example", i), googlebotUA, "192.0.2.10", false)
		}
		r.flushOnce(true)
		got := crawlerSiteRows(t, d)
		if len(got) != siteCapPerMinute+1 {
			t.Fatalf("%d per-site rows, want the cap (%d) and %s", len(got), siteCapPerMinute, OtherSite)
		}
		if got[OtherSite+"/Googlebot"].total != over || got["h0.example/Googlebot"].total != 1 {
			t.Errorf("%s holds %d requests (want %d), h0.example %d (want 1)",
				OtherSite, got[OtherSite+"/Googlebot"].total, over, got["h0.example/Googlebot"].total)
		}
	})
}

// While nothing drains the per-site buckets -- a schema update's hold, a
// database that refuses writes -- they stop growing at their bound: a site
// and crawler with no bucket yet are counted under OtherSite, a pair that has
// one goes on counting under its own name, and the sites still add up to the
// install-wide row.
func TestCrawlerSiteBucketsStopGrowingAtTheirBound(t *testing.T) {
	prev := crawlerSiteBucketsMax
	crawlerSiteBucketsMax = 3
	t.Cleanup(func() { crawlerSiteBucketsMax = prev })
	r, d := crawlerSiteReader(t)
	d.HoldWrites(true) // nothing is flushed
	for i := 0; i < 3; i++ {
		r.onLine(crawlerLine(fmt.Sprintf("s%d.example.com", i), "192.0.2.10", 0, 0, googlebotUA))
	}
	r.flushOnce(true)
	for i := 3; i < 8; i++ { // five more sites: past the bound
		r.onLine(crawlerLine(fmt.Sprintf("s%d.example.com", i), "192.0.2.10", 1, 0, googlebotUA))
	}
	r.onLine(crawlerLine("s0.example.com", "192.0.2.10", 0, 0, googlebotUA)) // a site that has its bucket
	d.HoldWrites(false)
	r.flushOnce(true)

	wantSiteRows(t, crawlerSiteRows(t, d), map[string]crawlerSiteRow{
		"s0.example.com/Googlebot": {total: 2},
		"s1.example.com/Googlebot": {total: 1},
		"s2.example.com/Googlebot": {total: 1},
		OtherSite + "/Googlebot":   {total: 5, served: 5},
	})
	if n, total, served := crawlerDetailTotals(t, d, "Googlebot"); n != 1 || total != 9 || served != 5 {
		t.Errorf("unmask_crawler_detail_hourly: %d row(s), total %d, served %d; want 1 row, 9, 5", n, total, served)
	}
}

// A flush that fails puts the per-site buckets back, all four counters, and
// the install-wide ones beside them; the retry writes them with what was
// counted since: once, not twice.
func TestFailedFlushPutsTheCrawlerSiteRowsBack(t *testing.T) {
	r, d := crawlerSiteReader(t)
	r.SetCrawlerRangeCheck(func(name, ip string) bool { return ip == "192.0.2.10" })
	r.onLine(crawlerLine("a.example.com", "192.0.2.10", 0, 0, googlebotUA))
	r.onLine(crawlerLine("a.example.com", "198.51.100.7", 0, 1, googlebotUA))
	r.onLine(crawlerLine("a.example.com", "198.51.100.7", 1, 0, googlebotUA))
	if _, err := d.Exec(`ALTER TABLE unmask_crawler_site_hourly RENAME TO unmask_crawler_site_hourly_away`); err != nil {
		t.Fatal(err)
	}
	r.flushOnce(true) // the per-site statement fails
	if _, err := d.Exec(`ALTER TABLE unmask_crawler_site_hourly_away RENAME TO unmask_crawler_site_hourly`); err != nil {
		t.Fatal(err)
	}
	if got := crawlerSiteRows(t, d); len(got) != 0 {
		t.Fatalf("the failed flush left per-site rows behind: %v", got)
	}
	if n, _, _ := crawlerDetailTotals(t, d, "Googlebot"); n != 0 {
		t.Fatalf("the failed flush left its install-wide row behind: the statements before the failing one were not rolled back")
	}
	r.onLine(crawlerLine("a.example.com", "192.0.2.10", 0, 0, googlebotUA)) // counted since
	r.flushOnce(true)
	got := crawlerSiteRows(t, d)["a.example.com/Googlebot"]
	if want := (crawlerSiteRow{total: 4, served: 1, verified: 2, named: 1}); got != want {
		t.Fatalf("after the retry: %+v, want %+v", got, want)
	}
	if n, total, served := crawlerDetailTotals(t, d, "Googlebot"); n != 1 || total != 4 || served != 1 {
		t.Errorf("unmask_crawler_detail_hourly after the retry: %d row(s), total %d, served %d; want 1 row, 4, 1", n, total, served)
	}
	r.flushOnce(true)
	if again := crawlerSiteRows(t, d)["a.example.com/Googlebot"]; again != got {
		t.Fatalf("a second flush wrote again: %+v", again)
	}
}
