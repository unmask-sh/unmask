package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func reuseTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// insReuse writes one (minute, site, ip, kind) row minAgo minutes back.
func insReuse(t *testing.T, d *db.DB, site, ip, kind, ja4 string, cnt, minAgo int) {
	t.Helper()
	min := time.Now().Unix()/60 - int64(minAgo)
	ls := time.Now().Add(-time.Duration(minAgo) * time.Minute).UTC().Format("2006-01-02 15:04:05.000")
	if _, err := d.Exec(
		`INSERT INTO unmask_cookie_ip_minute (bucket_min, site, ip, kind, ja4, ua, cnt, last_seen)
		 VALUES (?, ?, ?, ?, ?, 'UA', ?, ?)`,
		min, site, events.PackIP(ip), kind, ja4, cnt, ls); err != nil {
		t.Fatal(err)
	}
}

// TestCookieReuseSeparatesKinds: the card renders one section per cookie kind,
// so a query for one kind must never fold in the other.  This matters in the
// direction PoW -> CAPTCHA especially: PoW volume runs several times the CAPTCHA
// volume, so a leak would bury the section whose rows are actually suspicious.
func TestCookieReuseSeparatesKinds(t *testing.T) {
	d := reuseTestDB(t)
	insReuse(t, d, "s1", "1.2.3.4", "captcha", "t13d_a", 5, 10)
	insReuse(t, d, "s1", "1.2.3.4", "pow", "t13d_b", 900, 10)
	insReuse(t, d, "s1", "9.9.9.9", "pow", "t13d_c", 40, 10)

	cap1, err := CookieReuseTopIPs(context.Background(), d, "s1", "captcha", nil, 24, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(cap1) != 1 || cap1[0].IP != "1.2.3.4" || cap1[0].Requests != 5 {
		t.Fatalf("captcha section = %+v, want just the 5-request captcha row", cap1)
	}

	pow, err := CookieReuseTopIPs(context.Background(), d, "s1", "pow", nil, 24, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(pow) != 2 || pow[0].IP != "1.2.3.4" || pow[0].Requests != 900 {
		t.Fatalf("pow section = %+v, want both pow rows ranked by volume", pow)
	}
}

// TestCookieReuseJA4Count: volume alone cannot read a PoW row, because every
// ordinary visitor holds a PoW cookie and a carrier NAT out-requests any single
// scraper just by having many people behind it.  The fingerprint spread is what
// separates them, so the column has to actually count distinct JA4s per IP.
func TestCookieReuseJA4Count(t *testing.T) {
	d := reuseTestDB(t)
	// Shared egress: many fingerprints behind one address.
	for i, ja4 := range []string{"t13d_a", "t13d_b", "t13d_c", "t13d_d"} {
		insReuse(t, d, "s1", "10.0.0.1", "pow", ja4, 100, 10+i)
	}
	// One client riding one solved cookie: a single fingerprint, high volume.
	for i := 0; i < 4; i++ {
		insReuse(t, d, "s1", "10.0.0.2", "pow", "t13d_z", 100, 10+i)
	}

	rows, err := CookieReuseTopIPs(context.Background(), d, "s1", "pow", nil, 24, 30)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, r := range rows {
		got[r.IP] = r.JA4Count
	}
	if got["10.0.0.1"] != 4 {
		t.Errorf("shared-egress IP JA4Count = %d, want 4", got["10.0.0.1"])
	}
	if got["10.0.0.2"] != 1 {
		t.Errorf("single-client IP JA4Count = %d, want 1", got["10.0.0.2"])
	}
	// Both IPs made the same number of requests, so without JA4Count the
	// operator has nothing to tell them apart -- which is the whole point of
	// showing the column on the PoW section.
	if len(rows) != 2 || rows[0].Requests != rows[1].Requests {
		t.Fatalf("expected two IPs tied on volume, got %+v", rows)
	}
}

// TestPruneKeepsCaptchaDropsOldPow: PoW rows expire ahead of the shared window
// because a PoW _bv lives 7 days by default -- past two lifetimes the count
// stops describing one cookie and starts summing generations -- and because
// PoW volume would otherwise grow this table by an order of magnitude.
// CAPTCHA rows must keep the full window.
func TestPruneKeepsCaptchaDropsOldPow(t *testing.T) {
	d := reuseTestDB(t)
	const day = 1440
	insReuse(t, d, "s1", "1.1.1.1", "captcha", "t13d_a", 1, 20*day) // inside 32d
	insReuse(t, d, "s1", "2.2.2.2", "pow", "t13d_b", 1, 20*day)     // outside 15d
	insReuse(t, d, "s1", "3.3.3.3", "pow", "t13d_c", 1, 2*day)      // inside 15d
	// A second cookie lifetime: gone under the old 8-day cap, and exactly what
	// widening to 15 days is meant to keep.
	insReuse(t, d, "s1", "4.4.4.4", "pow", "t13d_d", 1, 10*day)

	if err := PruneHourly(context.Background(), d); err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	rows, err := d.Query(`SELECT ip, kind FROM unmask_cookie_ip_minute`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var kind string
		if err := rows.Scan(&raw, &kind); err != nil {
			t.Fatal(err)
		}
		got[ipFromBytes(raw)+"/"+kind] = true
	}
	if !got["1.1.1.1/captcha"] {
		t.Error("a 20-day-old CAPTCHA row was pruned; that section keeps the full 32-day window")
	}
	if got["2.2.2.2/pow"] {
		t.Error("a 20-day-old PoW row survived; PoW is capped at 15 days")
	}
	if !got["3.3.3.3/pow"] {
		t.Error("a 2-day-old PoW row was pruned; it is well inside the 15-day window")
	}
	if !got["4.4.4.4/pow"] {
		t.Error("a 10-day-old PoW row was pruned; the window covers two 7-day cookie lifetimes")
	}
}
