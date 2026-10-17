package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The install-wide request composition reads the hours the fold has settled
// from the hourly rollup and the minute table only around them: the partial
// hour the window opens in and the hours past the cursor.  Minute rows inside
// a settled hour are the rollup's source, not a second count.
func TestTrafficRequestsReadsSettledHoursFromRollup(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ins := func(q string, args ...any) {
		t.Helper()
		if _, err := d.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	minute := func(bm int64, site, kind string, cnt int) {
		t.Helper()
		ins(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?, ?, ?, ?)`, bm, site, kind, cnt)
	}
	hour := func(h int64, kind string, cnt int) {
		t.Helper()
		ins(`INSERT INTO unmask_aggregate_hourly (bucket_hour, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, ?)`,
			time.Unix(h*3600, 0).UTC().Format("2006-01-02 15"), hkCookiePass, kind, cnt)
	}

	// The window opens half way through hour H0 and runs into H6; the fold
	// has settled through H3.
	h0 := int64(500_000)
	cutoff, until := h0*60+30, (h0+6)*60+10
	ins(`INSERT INTO unmask_aggregate_state (name, last_id) VALUES (?, ?)`, installWideState, h0+3)

	minute(h0*60+29, "a", "total", 100) // before the window
	minute(h0*60+30, "a", "total", 5)   // the opening partial hour
	minute(h0*60+59, "b", "pow", 2)
	minute((h0+1)*60+5, "a", "total", 1000) // inside a settled hour: the rollup stands for it
	hour(h0, "total", 999)                  // the opening hour's rollup: not wholly inside
	hour(h0+1, "total", 40)
	hour(h0+2, "total", 30)
	hour(h0+3, "pow", 3)
	hour(h0+3, "captcha", 1)
	hour(h0+4, "total", 777)           // past the cursor: the minutes stand for it
	minute((h0+4)*60, "a", "total", 7) // past the cursor
	minute((h0+6)*60+10, "b", "challenge_served", 4)

	c, err := trafficRequestsFrom(context.Background(), d, cutoff, until, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Total != 82 || c.PowPass != 5 || c.CaptchaPass != 1 || c.Passed != 6 || c.Challenged != 4 || !c.OK {
		t.Errorf("install-wide: %+v, want total 82 (5+40+30+7), pow 5, captcha 1, challenged 4", c)
	}

	// A site-scoped read has no rollup: the window's minutes, settled or not.
	c, err = trafficRequestsFrom(context.Background(), d, cutoff, until, "a")
	if err != nil {
		t.Fatal(err)
	}
	if c.Total != 1012 || c.PowPass != 0 {
		t.Errorf("site a: %+v, want total 1012 (5+1000+7) from the minutes alone", c)
	}

	// Before the fold ever ran there is no cursor, and the minutes are all
	// there is -- the read of old.
	ins(`DELETE FROM unmask_aggregate_state WHERE name = ?`, installWideState)
	c, err = trafficRequestsFrom(context.Background(), d, cutoff, until, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Total != 1012 || c.PowPass != 2 || c.Challenged != 4 {
		t.Errorf("no cursor: %+v, want total 1012, pow 2, challenged 4 from the minutes", c)
	}

	// A cursor at or past the current hour never pulls the live hour into the
	// rollup read: the minutes of the current hour still count.
	ins(`INSERT INTO unmask_aggregate_state (name, last_id) VALUES (?, ?)`, installWideState, h0+6)
	c, err = trafficRequestsFrom(context.Background(), d, cutoff, until, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Challenged != 4 || c.Total != 5+40+30+777 {
		t.Errorf("cursor in the live hour: %+v, want challenged 4 and total 852 (5+40+30+777)", c)
	}
}
