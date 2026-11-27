package nginxlog

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
)

// TestMariaDB_EveryCrawlerCategoryIsWritten: a request of each category the
// classifier names is written to the three crawler tables, and the rest of
// the minute's flush with it.
//
// The category column was VARCHAR(16), and "notification-preview" is twenty
// characters.  Under MariaDB's default sql_mode a value longer than its
// column is an error (1406) that rolls back the transaction it rides in --
// here the whole minute's flush.  The rows return to memory and are tried
// again a minute later, the same value among them: one request from Apple's
// notification-preview fetcher, and no per-minute table was written again
// until the daemon was restarted.  Migration 0054 widens the three columns.
// Skips unless UNMASK_TEST_MARIADB_HOST is set (= make test-mariadb).
func TestMariaDB_EveryCrawlerCategoryIsWritten(t *testing.T) {
	_, d := mariadbReader(t)
	const (
		site    = "nginxlog-mariadb-cat"
		crawler = "MdbCategoryBot"
	)
	cleanup := func() {
		_, _ = d.Exec(`DELETE FROM unmask_crawler_site_hourly WHERE crawler = ?`, crawler)
		_, _ = d.Exec(`DELETE FROM unmask_crawler_detail_hourly WHERE crawler = ?`, crawler)
		// The per-minute table has the category for its whole key; the
		// database is the tests' own, so the categories' rows go.
		for _, cat := range classify.CrawlerTagOrder {
			_, _ = d.Exec(`DELETE FROM unmask_crawler_minute WHERE category = ?`, cat)
		}
		_, _ = d.Exec(`DELETE FROM unmask_cookie_ip_minute WHERE site = ?`, site)
	}
	cleanup()
	defer cleanup()

	r := &Reader{
		d:               d,
		buckets:         map[bucketKey]*bucket{},
		crawlerBuckets:  map[crawlerKey]*crawlerBucket{},
		cookieIPBuckets: map[cookieIPKey]*cookieIPBucket{},
	}
	// The category is the classifier's word for the User-Agent; the test
	// hands each one over as the UA says it.
	r.SetCrawlerClassifier(func(ua string) string { return strings.TrimPrefix(ua, "category=") })
	r.SetCrawlerNamer(func(ua, tag string) string { return crawler })
	for _, cat := range classify.CrawlerTagOrder {
		r.bumpCrawler(site, "category="+cat, false, false, "192.0.2.10")
	}
	// A row of another table in the same flush: it is written only if the
	// transaction as a whole is.
	r.BumpCookieIP(site, "203.0.113.30", "t13d1516h2_8daaf6152771_02713d6af862", "Mozilla/5.0 (plain)", "pow")
	r.flushOnce(true)

	for _, q := range []struct{ table, where string }{
		{"unmask_crawler_minute", `1 = 1`},
		{"unmask_crawler_detail_hourly", `crawler = '` + crawler + `'`},
		{"unmask_crawler_site_hourly", `crawler = '` + crawler + `'`},
	} {
		rows, err := d.Query(`SELECT DISTINCT category FROM ` + q.table + ` WHERE ` + q.where)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			got[c] = true
		}
		rows.Close()
		for _, cat := range classify.CrawlerTagOrder {
			if !got[cat] {
				t.Errorf("%s: category %q (%d characters) was not written", q.table, cat, len(cat))
			}
		}
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_cookie_ip_minute WHERE site = ?`, site).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("the row that rode in the same flush: %d written, want 1", n)
	}
	r.mu.Lock()
	left := len(r.crawlerBuckets)
	r.mu.Unlock()
	if left != 0 {
		t.Errorf("%d crawler bucket(s) went back into memory: the flush was refused", left)
	}
}
