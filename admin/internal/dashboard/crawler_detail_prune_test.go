package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// PruneHourly now prunes the per-crawler drill-down (unmask_crawler_detail_hourly,
// the AI-card trend sparkline source) at the fixed 32-day aggregate window
// (hourlyKeep) -- decoupled from events_retention_days.  So a high-volume node
// can lower raw-event retention to reclaim disk without shortening the crawler
// trend, which now tracks the dashboard's 30-day range like every other
// aggregate.  Rows past hourlyKeep go; rows inside stay.
func TestPruneHourlyPrunesCrawlerDetailAtFixedWindow(t *testing.T) {
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
	ins(1, "recent")                 // 1h ago            -> keep
	ins(24*(hourlyKeep-2), "inside") // ~30d ago (inside) -> keep
	ins(24*(hourlyKeep+5), "old")    // ~37d ago (past)   -> prune

	if err := PruneHourly(context.Background(), d); err != nil {
		t.Fatal(err)
	}

	var cnt int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_crawler_detail_hourly`).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 2 {
		t.Errorf("remaining=%d, want 2 (recent + inside-32d) -- PruneHourly did not prune crawler_detail at the fixed window", cnt)
	}
	var oldLeft int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_crawler_detail_hourly WHERE crawler='old'`).Scan(&oldLeft); err != nil {
		t.Fatal(err)
	}
	if oldLeft != 0 {
		t.Errorf("the >32d 'old' row survived (=%d) -- crawler_detail is not pruned by PruneHourly", oldLeft)
	}
}
