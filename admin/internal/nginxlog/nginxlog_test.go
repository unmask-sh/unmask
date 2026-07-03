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

	// Honeypot line: hpuri= carries the tripped URL, and ua= after it still
	// parses (the hpuri group sits before the greedy ua group).
	hp := `<134>1749000000.9 site=shop.example.com kind= fc=1 hp=1 ip=9.9.9.9 ` +
		`ja4=t13d1516h2 hpuri=/wp-login.php ua=curl/8.1`
	p3, ok := r.parse(hp)
	if !ok {
		t.Fatal("parse failed on a honeypot line with hpuri=")
	}
	if !p3.hp || p3.hpuri != "/wp-login.php" || p3.ua != "curl/8.1" || p3.ip != "9.9.9.9" {
		t.Errorf("honeypot line fields wrong: %+v", p3)
	}
	// A line without hpuri= leaves it empty (backward-compat with older nginx).
	if p.hpuri != "" {
		t.Errorf("hpuri should be empty on a no-hpuri line: %q", p.hpuri)
	}
}

// TestParseNoJA4Placeholder: nginx logs an unavailable $effective_ja4 as "-"
// (TLS session resumption etc.).  The parser must normalize it to "" AND keep
// the later fields anchored -- an earlier charset refused the "-", silently
// blanking hpuri/ua on exactly those lines, so a resumption-visit honeypot ban
// was recorded with a bare "honeypot" reason instead of its trip URL.
func TestParseNoJA4Placeholder(t *testing.T) {
	r := &Reader{}

	// The real-world shape from the tool1-us incident: second honeypot trip
	// over a resumed session, ja4=- but hpuri/ua present.
	line := `<134>1751400000.123 site=tool1-us kind= fc=0 hp=1 ip=20.220.217.32 ` +
		`ja4=- hpuri=//cgi-bin/index.php ua=Mozilla/5.0 zgrab/0.x`
	p, ok := r.parse(line)
	if !ok {
		t.Fatal("parse failed on a ja4=- line")
	}
	if p.ja4 != "" {
		t.Errorf(`ja4 "-" not normalized to empty: %q`, p.ja4)
	}
	if !p.hp || p.ip != "20.220.217.32" {
		t.Errorf("hp/ip lost on a ja4=- line: %+v", p)
	}
	if p.hpuri != "//cgi-bin/index.php" {
		t.Errorf("hpuri lost on a ja4=- line (chained-group regression): %q", p.hpuri)
	}
	if !strings.Contains(p.ua, "zgrab") {
		t.Errorf("ua lost on a ja4=- line: %q", p.ua)
	}

	// Empty value (ja4= with nothing) parses the same way.
	line2 := `<134>1751400000.5 site=default kind= fc=0 hp=1 ip=9.9.9.9 ja4= hpuri=/x ua=curl/8`
	p2, ok := r.parse(line2)
	if !ok {
		t.Fatal("parse failed on an empty-ja4 line")
	}
	if p2.ja4 != "" || p2.hpuri != "/x" || p2.ua != "curl/8" {
		t.Errorf("empty-ja4 line fields wrong: %+v", p2)
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

	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", false)  // passed
	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", false)  // passed
	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", true)   // served (challenged)
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

// TestCrawlerDetailAggregation drives bumpCrawler with a namer wired and
// checks the per-crawler rows land in unmask_crawler_detail_hourly, and that
// they sum back to the unmask_crawler_minute category total (the card + its
// drill-down popover must agree).
func TestCrawlerDetailAggregation(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}

	r := &Reader{
		d:                    d,
		buckets:              map[bucketKey]*bucket{},
		crawlerBuckets:       map[crawlerKey]*crawlerBucket{},
		crawlerDetailBuckets: map[crawlerDetailKey]*crawlerBucket{},
	}
	r.SetCrawlerClassifier(func(ua string) string {
		if strings.Contains(ua, "Googlebot") || strings.Contains(ua, "bingbot") {
			return "search-engine"
		}
		return ""
	})
	r.SetCrawlerNamer(func(ua, tag string) string {
		switch {
		case strings.Contains(ua, "Googlebot"):
			return "Googlebot"
		case strings.Contains(ua, "bingbot"):
			return "Bingbot"
		default:
			return "other"
		}
	})

	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", false)  // Googlebot passed
	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", false)  // Googlebot passed
	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", true)   // Googlebot served
	r.bumpCrawler("Mozilla/5.0 (compatible; bingbot/2.0)", false)    // Bingbot passed
	r.bumpCrawler("Mozilla/5.0 (Windows NT 10.0) Chrome/120", false) // not a crawler -> ignored

	r.flushOnce(true)

	ctx := context.Background()
	got := map[string][2]int{} // crawler -> {total, served}
	rows, err := d.QueryContext(ctx,
		`SELECT crawler, total, served FROM unmask_crawler_detail_hourly WHERE category = 'search-engine'`)
	if err != nil {
		t.Fatalf("query crawler_detail_hourly: %v", err)
	}
	for rows.Next() {
		var name string
		var total, served int
		if err := rows.Scan(&name, &total, &served); err != nil {
			t.Fatal(err)
		}
		got[name] = [2]int{total, served}
	}
	rows.Close()

	if got["Googlebot"] != [2]int{3, 1} {
		t.Errorf("Googlebot detail = %v, want [3 1]", got["Googlebot"])
	}
	if got["Bingbot"] != [2]int{1, 0} {
		t.Errorf("Bingbot detail = %v, want [1 0]", got["Bingbot"])
	}
	if len(got) != 2 {
		t.Errorf("want exactly 2 detail crawlers, got %d (%v)", len(got), got)
	}

	// Consistency: the detail rows must sum to the crawler_minute category total.
	var catTotal, catServed int
	if err := d.QueryRowContext(ctx,
		`SELECT total, served FROM unmask_crawler_minute WHERE category = 'search-engine'`).
		Scan(&catTotal, &catServed); err != nil {
		t.Fatalf("query crawler_minute: %v", err)
	}
	var sumTotal, sumServed int
	for _, v := range got {
		sumTotal += v[0]
		sumServed += v[1]
	}
	if sumTotal != catTotal || sumServed != catServed {
		t.Errorf("detail sum (total=%d served=%d) != category (total=%d served=%d)",
			sumTotal, sumServed, catTotal, catServed)
	}
}

// TestCrawlerDetailNamerUnset: with a classifier but no namer, only the
// per-category crawler_minute aggregation runs -- the detail table stays empty
// (the drill-down degrades cleanly to "no breakdown").
func TestCrawlerDetailNamerUnset(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	r := &Reader{
		d:                    d,
		buckets:              map[bucketKey]*bucket{},
		crawlerBuckets:       map[crawlerKey]*crawlerBucket{},
		crawlerDetailBuckets: map[crawlerDetailKey]*crawlerBucket{},
	}
	r.SetCrawlerClassifier(func(ua string) string {
		if strings.Contains(ua, "Googlebot") {
			return "search-engine"
		}
		return ""
	})
	// no SetCrawlerNamer
	r.bumpCrawler("Mozilla/5.0 (compatible; Googlebot/2.1)", false)
	r.flushOnce(true)
	var nDetail, nCat int
	if err := d.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM unmask_crawler_detail_hourly`).Scan(&nDetail); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM unmask_crawler_minute`).Scan(&nCat); err != nil {
		t.Fatal(err)
	}
	if nDetail != 0 {
		t.Errorf("namer unset: want 0 detail rows, got %d", nDetail)
	}
	if nCat != 1 {
		t.Errorf("namer unset: per-category aggregation should still run, want 1 row, got %d", nCat)
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
