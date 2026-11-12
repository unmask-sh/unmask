package dashboard

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// The per-site crawler table (unmask_crawler_site_hourly) is an aggregate
// like the ones beside it: PruneHourly trims it at the fixed window
// (hourlyKeep), and the window audit measures it, so that a table the prune
// had forgotten would be found by doctor and not by a slow page months on.
// It holds a row per hour, site and crawler -- the widest of the crawler
// tables on an install with many sites -- so a backlog goes in chunks.
func TestPruneHourlyPrunesCrawlerSiteAtFixedWindow(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	nowHour := time.Now().Unix() / 3600
	ins := func(hoursAgo int64, site string) {
		t.Helper()
		if _, err := d.Exec(
			`INSERT INTO unmask_crawler_site_hourly (bucket_hour, site, category, crawler, total, served, verified, named) VALUES (?,?,?,?,?,?,?,?)`,
			nowHour-hoursAgo, site, "ai-training", "GPTBot", 10, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	ins(1, "recent.example.com")                 // 1h ago            -> keep
	ins(24*(hourlyKeep-2), "inside.example.com") // ~30d ago (inside) -> keep
	// A backlog past the window, more of it than one chunk takes.
	prev := pruneChunkRows
	pruneChunkRows = 4
	t.Cleanup(func() { pruneChunkRows = prev })
	for i := 0; i < 10; i++ {
		ins(24*(hourlyKeep+5), fmt.Sprintf("old%d.example.com", i)) // ~37d ago -> prune
	}

	audit := func() AggregateWindow {
		t.Helper()
		ws, err := AuditAggregateWindows(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range ws {
			if w.Table == "unmask_crawler_site_hourly" {
				return w
			}
		}
		t.Fatal("the window audit does not measure unmask_crawler_site_hourly")
		return AggregateWindow{}
	}
	if w := audit(); !w.Over {
		t.Errorf("a row 37 days old is not reported as past the window: %+v", w)
	}

	if err := PruneHourly(ctx, d); err != nil {
		t.Fatal(err)
	}
	var left, old int
	if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(site LIKE 'old%'), 0) FROM unmask_crawler_site_hourly`).Scan(&left, &old); err != nil {
		t.Fatal(err)
	}
	if left != 2 || old != 0 {
		t.Errorf("after the prune %d rows are left, %d of them past the window; want the 2 inside it", left, old)
	}
	if w := audit(); w.Over || w.Empty {
		t.Errorf("after the prune the table is still reported: %+v", w)
	}
}
