package nginxlog

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/unmask-sh/unmask/admin/internal/classify"
)

// mariadbColumnWidth is the width the MariaDB migrations leave a VARCHAR
// column of a table with: the last one a CREATE TABLE or a MODIFY of the
// numbered files declares.
func mariadbColumnWidth(t *testing.T, table, column string) int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "db", "migrations", "mariadb", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no MariaDB migrations to read: %v", err)
	}
	sort.Strings(files)
	create := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` + table + `\s*\((.*)`)
	alter := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + table + `\s+(.*)`)
	col := regexp.MustCompile(`(?im)(?:^|MODIFY\s+(?:COLUMN\s+)?|ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?)\s*` + column + `\s+VARCHAR\s*\(\s*(\d+)\s*\)`)
	width := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// Comment lines out, then statement by statement.
		var kept []string
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				kept = append(kept, l)
			}
		}
		for _, stmt := range strings.Split(strings.Join(kept, "\n"), ";") {
			body := ""
			if m := create.FindStringSubmatch(stmt); m != nil {
				body = m[1]
			} else if m := alter.FindStringSubmatch(stmt); m != nil {
				body = m[1]
			}
			if m := col.FindStringSubmatch(body); m != nil {
				width, _ = strconv.Atoi(m[1])
			}
		}
	}
	if width == 0 {
		t.Fatalf("the MariaDB migrations declare no width for %s.%s", table, column)
	}
	return width
}

// TestCrawlerCategoriesFitTheirColumn: every category the classifier names
// fits the column MariaDB keeps it in, in each of the three tables.  A
// category is one of a fixed set the readers ask for by name, so the writer
// does not cut it: one that is longer than its column is refused, and the
// minute's whole flush with it, every minute from then on ("notification-
// preview" against VARCHAR(16), until migration 0054).  A category added to
// classify.CrawlerTagOrder past the width fails here, not on an install.
func TestCrawlerCategoriesFitTheirColumn(t *testing.T) {
	for _, table := range []string{"unmask_crawler_minute", "unmask_crawler_detail_hourly", "unmask_crawler_site_hourly"} {
		w := mariadbColumnWidth(t, table, "category")
		for _, cat := range classify.CrawlerTagOrder {
			if n := utf8.RuneCountInString(cat); n > w {
				t.Errorf("%s.category is VARCHAR(%d) on MariaDB; category %q is %d characters", table, w, cat, n)
			}
		}
	}
}

// TestCrawlerNameWidthIsTheColumns: the width a crawler's name is cut to is
// the one the three tables that keep it have on MariaDB.
func TestCrawlerNameWidthIsTheColumns(t *testing.T) {
	for _, table := range []string{"unmask_crawler_detail_hourly", "unmask_crawler_site_hourly", "unmask_crawler_named_hourly"} {
		if w := mariadbColumnWidth(t, table, "crawler"); w != crawlerNameWidth {
			t.Errorf("%s.crawler is VARCHAR(%d) on MariaDB; a name is cut to %d", table, w, crawlerNameWidth)
		}
	}
}

// TestCrawlerNameIsOneTheColumnTakes: a name the namer hands over with a
// character cut in half (classify cuts a name at 48 bytes) is kept as UTF-8
// within the column's width.
func TestCrawlerNameIsOneTheColumnTakes(t *testing.T) {
	_, d := passReader(t)
	r := &Reader{
		d:              d,
		buckets:        map[bucketKey]*bucket{},
		crawlerBuckets: map[crawlerKey]*crawlerBucket{},
	}
	r.SetCrawlerClassifier(func(ua string) string { return "search-engine" })
	half := strings.Repeat("あ", 16)[:47] // 15 characters and two bytes of the 16th
	r.SetCrawlerNamer(func(ua, tag string) string { return half })
	r.bumpCrawler("a.example", "AnyBot/1.0", false, false, "192.0.2.10")
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.crawlerDetailBuckets) != 1 {
		t.Fatalf("%d drill-down bucket(s), want 1", len(r.crawlerDetailBuckets))
	}
	for k := range r.crawlerDetailBuckets {
		if !utf8.ValidString(k.crawler) || utf8.RuneCountInString(k.crawler) > crawlerNameWidth || k.crawler != strings.Repeat("あ", 15) {
			t.Errorf("the name kept is %q", k.crawler)
		}
	}
}
