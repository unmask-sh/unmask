package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestHourlyRequests(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/h.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Asia/Tokyo")
	// 10:30 JST on the 10th: today's 10 o'clock is the current hour.
	now := time.Date(2026, 10, 10, 10, 30, 0, 0, loc)
	ctx := context.Background()
	ins := func(at time.Time, site, kind string, cnt int) {
		if _, err := d.ExecContext(ctx, `INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?, ?, ?, ?)`, at.Unix()/60, site, kind, cnt); err != nil {
			t.Fatal(err)
		}
	}
	ins(time.Date(2026, 10, 10, 10, 5, 0, 0, loc), "a", "total", 7)   // today 10h
	ins(time.Date(2026, 10, 10, 10, 6, 0, 0, loc), "b", "total", 3)   // today 10h, another site
	ins(time.Date(2026, 10, 10, 10, 6, 0, 0, loc), "a", "pow", 2)     // not a total: ignored
	ins(time.Date(2026, 10, 10, 0, 0, 0, 0, loc), "a", "total", 5)    // today 0h, the first minute of the day
	ins(time.Date(2026, 10, 9, 23, 59, 0, 0, loc), "a", "total", 4)   // yesterday 23h, the last minute
	ins(time.Date(2026, 10, 9, 10, 15, 0, 0, loc), "a", "total", 9)   // yesterday 10h
	ins(time.Date(2026, 10, 8, 23, 59, 0, 0, loc), "a", "total", 100) // the day before: out of the window

	hc, err := HourlyRequests(ctx, d, "", loc, now)
	if err != nil {
		t.Fatal(err)
	}
	if !hc.OK || hc.NowHour != 10 {
		t.Errorf("ok=%v nowHour=%d", hc.OK, hc.NowHour)
	}
	if hc.Today[10] != 10 || hc.Today[0] != 5 || hc.Yesterday[23] != 4 || hc.Yesterday[10] != 9 {
		t.Errorf("today=%v yesterday=%v", hc.Today, hc.Yesterday)
	}
	var sum int
	for h := 0; h < 24; h++ {
		sum += hc.Today[h] + hc.Yesterday[h]
	}
	if sum != 28 {
		t.Errorf("two-day sum = %d, want 28 (the older row must be out)", sum)
	}
	// A site filter keeps that site's rows only.
	one, err := HourlyRequests(ctx, d, "b", loc, now)
	if err != nil || one.Today[10] != 3 || one.Yesterday[10] != 0 {
		t.Errorf("site b: %v today=%v yesterday=%v", err, one.Today, one.Yesterday)
	}
	// Nothing in the window: OK is false.
	none, err := HourlyRequests(ctx, d, "zzz", loc, now)
	if err != nil || none.OK {
		t.Errorf("empty site: err=%v ok=%v", err, none.OK)
	}
	// A nil database reads as empty rather than failing.
	if hc, err := HourlyRequests(ctx, nil, "", loc, now); err != nil || hc.OK {
		t.Errorf("nil db: %v %+v", err, hc)
	}
}
