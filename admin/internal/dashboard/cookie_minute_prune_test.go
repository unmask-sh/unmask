package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// unmask_cookie_minute feeds the 30-day cards and, until now, was the one
// minute-grained aggregate PruneHourly never trimmed: it had grown to 102 days
// on the busiest node against a page that shows 30.  It keeps the same 32-day
// window as the tables beside it.
func TestPruneHourlyPrunesCookieMinuteAtFixedWindow(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	nowMin := time.Now().Unix() / 60
	ins := func(minutesAgo int64, kind string) {
		if _, err := d.Exec(
			`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)`,
			nowMin-minutesAgo, "", kind, 10); err != nil {
			t.Fatal(err)
		}
	}
	ins(5, "total")                      // 5 minutes ago         -> keep
	ins(1440*(hourlyKeep-2), "total")    // ~30 days ago (inside) -> keep
	ins(1440*(hourlyKeep+5), "total")    // ~37 days ago (past)   -> prune
	ins(1440*(hourlyKeep+40), "captcha") // ~72 days ago (past)   -> prune

	if err := PruneHourly(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	var cnt, old int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_cookie_minute`).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_cookie_minute WHERE bucket_min < ?`, nowMin-1440*int64(hourlyKeep)).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if cnt != 2 || old != 0 {
		t.Errorf("remaining=%d past-window=%d, want 2 and 0: PruneHourly must trim unmask_cookie_minute at the %d-day window", cnt, old, hourlyKeep)
	}
}

// The first pass over a backlog runs in bounded transactions and carries on
// until the backlog is gone: with the chunk lowered to 100 rows, 350 old rows
// take four transactions and still all go, and the rows inside the window
// stay.
func TestPruneCookieMinuteBacklogGoesInChunks(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/c.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	orig := pruneChunkRows
	pruneChunkRows = 100
	t.Cleanup(func() { pruneChunkRows = orig })

	nowMin := time.Now().Unix() / 60
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 350; i++ { // 350 rows, 40..75 days old: all past the window
		if _, err := tx.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)`,
			nowMin-1440*40-int64(i)*144, "", "total", 1); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ { // 20 rows inside the window
		if _, err := tx.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)`,
			nowMin-int64(i)*60, "", "total", 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := pruneRowsInChunks(context.Background(), d, "unmask_cookie_minute", "bucket_min", nowMin-1440*int64(hourlyKeep)); err != nil {
		t.Fatal(err)
	}
	var cnt int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_cookie_minute`).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 20 {
		t.Errorf("remaining=%d, want 20: the chunked prune must keep going past the first chunk and stop at the window", cnt)
	}
}

// unmask_traffic_country_hourly was the other aggregate the prune never
// covered (102 days on tool1-jp, found by the window audit the day it was
// added).  Same 32-day window; its key is the unix hour.
func TestPruneHourlyPrunesCountryHourlyAtFixedWindow(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/h.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	nowHour := time.Now().Unix() / 3600
	ins := func(hoursAgo int64) {
		if _, err := d.Exec(`INSERT INTO unmask_traffic_country_hourly (bucket_hour, site, country, kind, cnt) VALUES (?,?,?,?,?)`,
			nowHour-hoursAgo, "", "JP", "total", 1); err != nil {
			t.Fatal(err)
		}
	}
	ins(1)
	ins(24 * (hourlyKeep - 2))
	ins(24 * (hourlyKeep + 5))
	ins(24 * 100)
	if err := PruneHourly(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	var cnt, old int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_traffic_country_hourly`).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_traffic_country_hourly WHERE bucket_hour < ?`, nowHour-24*int64(hourlyKeep)).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if cnt != 2 || old != 0 {
		t.Errorf("remaining=%d past-window=%d, want 2 and 0: PruneHourly must trim unmask_traffic_country_hourly at the %d-day window", cnt, old, hourlyKeep)
	}
}
