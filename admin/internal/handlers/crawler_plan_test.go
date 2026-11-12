package handlers

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// crawlerPlan joins the planner's detail lines for one statement.
func crawlerPlan(t *testing.T, h *Handler, stmt string, args ...any) string {
	t.Helper()
	rows, err := h.DB.Query("EXPLAIN QUERY PLAN "+stmt, args...)
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, stmt)
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("explain scan: %v", err)
		}
		sb.WriteString(detail)
		sb.WriteString(" | ")
	}
	return sb.String()
}

// TestCrawlerReadsGoThroughTheirIndexes: the per-site crawler table holds a
// row per hour, site and crawler, so on an install with many sites nearly all
// of a window's rows are other sites'.  A site's reads -- the card's
// categories, its drill-down, the CSV's day -- seek that site through the
// (site, bucket_hour) index and cost its own rows; the CSV's day for every
// site ranges over the hours by the table's key; and the checks around them
// (the table's two ends, the install-wide rows from before it began) are
// seeks.  None walks a table.  The database has no planner statistics, like
// one whose tables were just created by the migration.
func TestCrawlerReadsGoThroughTheirIndexes(t *testing.T) {
	h := crawlerHandler(t)
	nowHour := time.Now().Unix() / 3600
	tx, err := h.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for hr := int64(0); hr < 48; hr++ {
		for c := 0; c < 6; c++ {
			if _, err := tx.Exec(`INSERT INTO unmask_crawler_detail_hourly (bucket_hour, category, crawler, total, served) VALUES (?,?,?,?,?)`,
				nowHour-hr, "search-engine", fmt.Sprintf("Bot%d", c), 120, 12); err != nil {
				t.Fatal(err)
			}
			for s := 0; s < 12; s++ {
				if _, err := tx.Exec(`INSERT INTO unmask_crawler_site_hourly
					(bucket_hour, site, category, crawler, total, served, verified, named) VALUES (?,?,?,?,?,?,?,?)`,
					nowHour-hr, fmt.Sprintf("s%02d.example.com", s), "search-engine", fmt.Sprintf("Bot%d", c), 10, 1, 0, 0); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	since := nowHour - 24
	const site = "s03.example.com"

	for name, plan := range map[string]string{
		"a site's drill-down":     crawlerPlan(t, h, crawlerSiteDetailStmt, since, site),
		"a site's categories":     crawlerPlan(t, h, crawlerSiteCategoryStmt, since, site),
		"a site's day of the CSV": crawlerPlan(t, h, crawlersCSVDaySiteStmt, since, nowHour, site),
	} {
		if !strings.Contains(plan, "idx_crawler_site_site_hour (site=? AND bucket_hour>") {
			t.Errorf("%s does not seek the site through its index: %s", name, plan)
		}
		if strings.Contains(plan, "SCAN") {
			t.Errorf("%s walks a table or an index: %s", name, plan)
		}
	}
	// Every site's day of the CSV: the window's hours by the key, not the
	// site index from end to end.
	if plan := crawlerPlan(t, h, crawlersCSVDayStmt, since, nowHour); !strings.Contains(plan, "(bucket_hour>") ||
		strings.Contains(plan, "SCAN") || strings.Contains(plan, "idx_crawler_site_site_hour") {
		t.Errorf("every site's day of the CSV does not range over the window's hours by the key: %s", plan)
	}
	// The rest are seeks: each end of the per-site table, and the
	// install-wide rows from before it began.
	for name, plan := range map[string]string{
		"the per-site table's first hour":           crawlerPlan(t, h, crawlerSiteFirstHourStmt),
		"the per-site table's last hour":            crawlerPlan(t, h, crawlerSiteNewestStmt),
		"an install-wide row in the window":         crawlerPlan(t, h, crawlerDetailSinceStmt, since),
		"an install-wide row before the first hour": crawlerPlan(t, h, crawlerDetailBeforeStmt, since, nowHour-2),
	} {
		if strings.Contains(plan, "SCAN") {
			t.Errorf("%s walks the table or an index: %s", name, plan)
		}
	}
}
