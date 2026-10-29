package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// insPass writes one (day, site, ip) row of unmask_pass_ip_day daysAgo days
// back.
func insPass(t *testing.T, d *db.DB, site, ip string, daysAgo, cookies, ja4s, cnt, judged, peak int, ja4 string) {
	t.Helper()
	day := time.Now().Unix()/86400 - int64(daysAgo)
	ls := time.Now().Add(-time.Duration(daysAgo) * 24 * time.Hour).UTC().Format("2006-01-02 15:04:05.000")
	if _, err := d.Exec(
		`INSERT INTO unmask_pass_ip_day (bucket_day, site, ip, cookies, ja4s, ja4, cnt, judged, peak_hour, ua, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'UA', ?)`,
		day, site, events.PackIP(ip), cookies, ja4s, ja4, cnt, judged, peak, ls); err != nil {
		t.Fatal(err)
	}
}

// TestPassIPTopBusiestDayAndSums: over several days an address shows its
// busiest day's cookie count, fingerprint count and hourly peak, and the sum
// of its requests; the rows order by cookies, or by the peak; the site filter
// and the window hold.
func TestPassIPTopBusiestDayAndSums(t *testing.T) {
	d := reuseTestDB(t)
	ctx := context.Background()
	insPass(t, d, "s1", "10.0.0.1", 0, 5, 2, 100, 80, 40, "t13d_a")
	insPass(t, d, "s1", "10.0.0.1", 1, 9, 3, 200, 150, 20, "t13d_a")
	insPass(t, d, "s1", "10.0.0.2", 0, 1, 1, 950, 900, 900, "t13d_b")
	insPass(t, d, "s2", "10.0.0.3", 0, 50, 1, 10, 10, 1, "t13d_c") // another site
	insPass(t, d, "s1", "10.0.0.4", 20, 99, 1, 1, 1, 1, "t13d_d")  // outside a week

	rows, err := PassIPTop(ctx, d, "s1", nil, 7*24, 30, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].IP != "10.0.0.1" || rows[1].IP != "10.0.0.2" {
		t.Fatalf("by cookies: %+v, want 10.0.0.1 then 10.0.0.2", rows)
	}
	r := rows[0]
	if r.Cookies != 9 || r.Peak != 40 || r.JA4Count != 3 || r.Requests != 300 || r.Judged != 230 || r.JA4 != "t13d_a" {
		t.Errorf("10.0.0.1 over two days: cookies=%d peak=%d ja4s=%d reqs=%d judged=%d ja4=%q; want 9 / 40 / 3 / 300 / 230 / t13d_a",
			r.Cookies, r.Peak, r.JA4Count, r.Requests, r.Judged, r.JA4)
	}

	rows, err = PassIPTop(ctx, d, "s1", nil, 7*24, 30, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].IP != "10.0.0.2" || rows[0].Peak != 900 {
		t.Fatalf("by peak: %+v, want 10.0.0.2 (900) first", rows)
	}

	rows, err = PassIPTop(ctx, d, "", nil, 7*24, 30, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].IP != "10.0.0.3" {
		t.Fatalf("all sites: %+v, want the other site's 50-cookie address first of three", rows)
	}
}

// TestPruneDropsOldPassDays: the per-day pass rows keep the PoW rows'
// window and no more.
func TestPruneDropsOldPassDays(t *testing.T) {
	d := reuseTestDB(t)
	insPass(t, d, "s1", "1.1.1.1", 2, 1, 1, 1, 1, 1, "t13d_a")
	insPass(t, d, "s1", "2.2.2.2", 20, 1, 1, 1, 1, 1, "t13d_b")
	if err := PruneHourly(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	rows, err := d.Query(`SELECT ip FROM unmask_pass_ip_day`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		got[ipFromBytes(raw)] = true
	}
	if !got["1.1.1.1"] || got["2.2.2.2"] || len(got) != 1 {
		t.Errorf("after the prune: %v, want the 2-day-old row alone (the 20-day-old one is past the 15-day window)", got)
	}
}
