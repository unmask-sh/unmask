package nginxlog

import (
	"strings"
	"testing"
)

// TestMariaDB_CrawlerSiteUpsert: the per-site crawler upsert in MariaDB's
// dialect -- eight columns, the site in the key, the four counters adding up
// on a second flush of the same hour -- since a statement that fails here
// rolls back every aggregate in the flush, once a minute, for the whole life
// of the install.  The install-wide drill-down is written in the same flush
// by the statement it always had, one row for the two sites.  Skips unless
// UNMASK_TEST_MARIADB_HOST is set (= make test-mariadb).  The rows carry a
// category of their own and are removed.
func TestMariaDB_CrawlerSiteUpsert(t *testing.T) {
	_, d := mariadbReader(t)
	const category = "mdb-crawl-site"
	cleanup := func() {
		_, _ = d.Exec(`DELETE FROM unmask_crawler_site_hourly WHERE category = ?`, category)
		_, _ = d.Exec(`DELETE FROM unmask_crawler_detail_hourly WHERE category = ?`, category)
		_, _ = d.Exec(`DELETE FROM unmask_crawler_minute WHERE category = ?`, category)
		_, _ = d.Exec(`DELETE FROM unmask_crawler_named_hourly WHERE crawler = 'MdbTestBot'`)
	}
	cleanup()
	defer cleanup()

	newReader := func() *Reader {
		r := &Reader{
			d:              d,
			buckets:        map[bucketKey]*bucket{},
			crawlerBuckets: map[crawlerKey]*crawlerBucket{},
		}
		r.SetCrawlerClassifier(func(ua string) string {
			if strings.Contains(ua, "MdbTestBot") {
				return category
			}
			return ""
		})
		r.SetCrawlerNamer(func(ua, tag string) string { return "MdbTestBot" })
		r.SetCrawlerRangeCheck(func(name, ip string) bool { return ip == "192.0.2.10" })
		return r
	}
	read := func() map[string]crawlerSiteRow {
		t.Helper()
		rows, err := d.Query(`SELECT site, total, served, verified, named FROM unmask_crawler_site_hourly WHERE category = ?`, category)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]crawlerSiteRow{}
		for rows.Next() {
			var site string
			var v crawlerSiteRow
			if err := rows.Scan(&site, &v.total, &v.served, &v.verified, &v.named); err != nil {
				t.Fatal(err)
			}
			out[site] = v
		}
		return out
	}
	installWide := func() (n, total, served int) {
		t.Helper()
		if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(total), 0), COALESCE(SUM(served), 0)
			FROM unmask_crawler_detail_hourly WHERE category = ?`, category).Scan(&n, &total, &served); err != nil {
			t.Fatal(err)
		}
		return n, total, served
	}

	const ua = "Mozilla/5.0 (compatible; MdbTestBot/1.0)"
	r := newReader()
	r.bumpCrawler("a.example.com", ua, false, false, "192.0.2.10")
	r.bumpCrawler("a.example.com", ua, true, false, "198.51.100.7")
	r.bumpCrawler("a.example.com", ua, false, true, "198.51.100.7")
	r.bumpCrawler("b.example.com", ua, false, false, "192.0.2.10")
	r.flushOnce(true)
	got := read()
	if a, b := got["a.example.com"], got["b.example.com"]; len(got) != 2 ||
		a != (crawlerSiteRow{total: 3, served: 1, verified: 1, named: 1}) || b != (crawlerSiteRow{total: 1, verified: 1}) {
		t.Fatalf("after the first flush: %+v; want a.example.com {3 1 1 1} and b.example.com {1 0 1 0}", got)
	}
	if n, total, served := installWide(); n != 1 || total != 4 || served != 1 {
		t.Errorf("install-wide after the first flush: %d row(s), total %d, served %d; want 1 row, 4, 1", n, total, served)
	}

	// The same hour again, as the next minute's flush (or a restarted daemon)
	// writes it: the rows' counters add up.
	r2 := newReader()
	r2.bumpCrawler("a.example.com", ua, true, false, "192.0.2.10")
	r2.bumpCrawler("a.example.com", ua, false, true, "198.51.100.8")
	r2.flushOnce(true)
	got = read()
	if a := got["a.example.com"]; len(got) != 2 || a != (crawlerSiteRow{total: 5, served: 2, verified: 2, named: 2}) {
		t.Fatalf("after the second flush: %+v; want a.example.com {5 2 2 2} and b.example.com unchanged", got)
	}
	if n, total, served := installWide(); n != 1 || total != 6 || served != 2 {
		t.Errorf("install-wide after the second flush: %d row(s), total %d, served %d; want 1 row, 6, 2", n, total, served)
	}
}
