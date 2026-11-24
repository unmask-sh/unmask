package dashboard

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestPruneHourlyKeepsLetThroughAWeek: both let-through tables are trimmed at
// letKeepDays, the counts with the addresses.  The page reads a week at most,
// and the counts are a row an hour for every site, ground and detail, each
// with a 1 KiB sketch: kept for the 32 days of the other hourly tables they
// would be the widest of them on an install with many sites, for nothing that
// reads them.  A backlog goes in chunks.
func TestPruneHourlyKeepsLetThroughAWeek(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	nowHour := time.Now().Unix() / 3600
	ins := func(hoursAgo int64, site string) {
		t.Helper()
		letSeedTotal(t, d, nowHour-hoursAgo, site, "nogate", "", 3, "203.0.113.7")
		letSeedAddr(t, d, nowHour-hoursAgo, site, "nogate", "", "203.0.113.7", 3, "/a")
	}
	ins(1, "recent.example")                  // an hour ago         -> kept
	ins(24*(letKeepDays-1), "inside.example") // inside the window   -> kept
	prev := pruneChunkRows
	pruneChunkRows = 4
	t.Cleanup(func() { pruneChunkRows = prev })
	for i := 0; i < 10; i++ {
		ins(24*(letKeepDays+2), fmt.Sprintf("old%d.example", i)) // past it, more than one chunk
	}
	// Inside the 32 days of the other hourly tables, and past this one's.
	ins(24*(hourlyKeep-2), "month.example")

	if err := PruneHourly(ctx, d); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"unmask_let_hourly", "unmask_let_ip_hourly"} {
		var left int
		if err := d.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if left != 2 {
			t.Errorf("%s: %d rows left, want the 2 inside %d days", table, left, letKeepDays)
		}
		var old int
		if err := d.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE bucket_hour < ?`, nowHour-letKeepDays*24).Scan(&old); err != nil {
			t.Fatal(err)
		}
		if old != 0 {
			t.Errorf("%s: %d rows older than %d days survived the prune", table, old, letKeepDays)
		}
	}
}
