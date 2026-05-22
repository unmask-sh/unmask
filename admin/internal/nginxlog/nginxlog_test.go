package nginxlog

import (
	"context"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestParseUA checks that the ua= field (last, space-containing) is extracted
// while the existing fields keep parsing — and that an old-format line with no
// ua= still parses.
func TestParseUA(t *testing.T) {
	r := &Reader{}

	withUA := `<134>1749000000.123 site=shop.example.com kind= fc=1 hp=0 ip=1.2.3.4 ` +
		`ja4=t13d1516h2 ua=Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
	p, ok := r.parse(withUA)
	if !ok {
		t.Fatal("parse failed on a line with ua=")
	}
	if p.site != "shop.example.com" || !p.fc || p.ip != "1.2.3.4" || p.ja4 != "t13d1516h2" {
		t.Errorf("fields wrong: %+v", p)
	}
	if !strings.Contains(p.ua, "Googlebot/2.1") || !strings.Contains(p.ua, "bot.html)") {
		t.Errorf("ua not fully captured: %q", p.ua)
	}

	// Old format (no ua=) still parses; ua is empty.
	old := `<134>1749000000.5 site=default kind=pow fc=0 hp=0 ip=2.3.4.5 ja4=t13d`
	p2, ok := r.parse(old)
	if !ok {
		t.Fatal("parse failed on an old-format line")
	}
	if p2.ua != "" || p2.kind != "pow" {
		t.Errorf("old line: ua=%q kind=%q", p2.ua, p2.kind)
	}
}

// TestCrawlerAggregation drives bumpCrawler + flushOnce and checks the rows
// land in unmask_crawler_minute with the expected total / served split.
func TestCrawlerAggregation(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}

	r := &Reader{
		d:              d,
		buckets:        map[bucketKey]*bucket{},
		crawlerBuckets: map[crawlerKey]*crawlerBucket{},
	}
	r.SetCrawlerClassifier(func(ua string) string {
		if strings.Contains(ua, "Googlebot") {
			return "search"
		}
		return ""
	})

	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", false) // passed
	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", false) // passed
	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", true)  // served (challenged)
	r.bumpCrawler("Mozilla/5.0 (Windows NT 10.0) Chrome/120", false) // not a crawler -> ignored
	r.bumpCrawler("", false)                                         // empty UA -> ignored

	r.flushOnce(true)

	var total, served int
	err = d.QueryRowContext(context.Background(),
		`SELECT total, served FROM unmask_crawler_minute WHERE category = 'search'`).
		Scan(&total, &served)
	if err != nil {
		t.Fatalf("query crawler_minute: %v", err)
	}
	if total != 3 || served != 1 {
		t.Errorf("search bucket: total=%d served=%d, want 3 / 1", total, served)
	}

	// the non-crawler / empty UA must not have created any other category row.
	var n int
	if err := d.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM unmask_crawler_minute`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("want exactly 1 crawler_minute row, got %d", n)
	}
}

// TestCrawlerClassifierUnset: with no classifier, bumpCrawler is a no-op (the
// feature degrades cleanly rather than panicking).
func TestCrawlerClassifierUnset(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	r := &Reader{d: d, buckets: map[bucketKey]*bucket{}, crawlerBuckets: map[crawlerKey]*crawlerBucket{}}
	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", false) // classifier nil -> no-op
	r.flushOnce(true)
	var n int
	if err := d.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM unmask_crawler_minute`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("classifier unset: want 0 rows, got %d", n)
	}
}
