package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestDayBucketTZ checks that a single event sitting near the UTC midnight
// boundary lands on different chart days when the operator selects UTC vs JST.
// Concretely: 2026-05-29 22:00:00 UTC = 2026-05-30 07:00 JST -> the event is
// "May 29" in UTC and "May 30" in Tokyo, and the query layer must reflect both.
func TestDayBucketTZ(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "tztest-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Seed a single phase='serve' event at 22:00 UTC two days ago, so it stays
	// inside the 7-day read window no matter when the test runs (a fixed past
	// date silently fell out of range once enough wall-clock days passed, which
	// made this test start failing).  22:00 UTC = 07:00 next-day JST, so the
	// event still straddles the day boundary: day N in UTC, day N+1 in Tokyo.
	base := time.Now().UTC().AddDate(0, 0, -2)
	seed := time.Date(base.Year(), base.Month(), base.Day(), 22, 0, 0, 0, time.UTC)
	tsUTC := seed.Format("2006-01-02 15:04:05.000")
	if _, err := d.Exec(
		`INSERT INTO unmask_event
			(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
			 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
		 VALUES ('','','','','1.2.3.4','UA','','',0,'serve',0,0,'','','{}',?)`, tsUTC); err != nil {
		t.Fatalf("seed: %v", err)
	}

	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatalf("load jst: %v", err)
	}

	ctx := context.Background()
	cases := []struct {
		name    string
		tz      *time.Location
		wantDay string
	}{
		{"utc", time.UTC, seed.Format("2006-01-02")},
		{"jst", jst, seed.In(jst).Format("2006-01-02")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, totals, err := DailyServeByKind(ctx, d, "", nil, 7, []string{}, c.tz)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if len(totals) != 1 {
				t.Fatalf("totals = %d rows, want 1", len(totals))
			}
			if totals[0].Date != c.wantDay {
				t.Errorf("date = %q, want %q (tz=%s)", totals[0].Date, c.wantDay, c.tz)
			}
			if totals[0].Req != 1 || totals[0].UniqIPs != 1 {
				t.Errorf("req=%d uniq=%d, want 1/1", totals[0].Req, totals[0].UniqIPs)
			}
		})
	}
}
