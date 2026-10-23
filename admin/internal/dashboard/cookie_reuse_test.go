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

// insReuse writes one (minute, site, ip, kind) row minAgo minutes back, every
// line judged.
func insReuse(t *testing.T, d *db.DB, site, ip, kind, ja4 string, cnt, minAgo int) {
	t.Helper()
	insReuseJudged(t, d, site, ip, kind, ja4, cnt, cnt, minAgo)
}

// insReuseJudged is insReuse with the judged count apart from the whole.
func insReuseJudged(t *testing.T, d *db.DB, site, ip, kind, ja4 string, cnt, judged, minAgo int) {
	t.Helper()
	min := time.Now().Unix()/60 - int64(minAgo)
	ls := time.Now().Add(-time.Duration(minAgo) * time.Minute).UTC().Format("2006-01-02 15:04:05.000")
	if _, err := d.Exec(
		`INSERT INTO unmask_cookie_ip_minute (bucket_min, site, ip, kind, ja4, ua, cnt, judged, last_seen)
		 VALUES (?, ?, ?, ?, ?, 'UA', ?, ?, ?)`,
		min, site, events.PackIP(ip), kind, ja4, cnt, judged, ls); err != nil {
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

// TestCookieReuseJudgedLeads: the ranking orders by the judged count -- the
// lines the gate judged, which is what the reuse cap counts -- and carries
// the whole beside it.  An address whose cookie rides mostly on static files
// and the challenge page's own parts ranks below one whose pages the gate
// judged, however many lines the log holds for it.
func TestCookieReuseJudgedLeads(t *testing.T) {
	d := reuseTestDB(t)
	insReuseJudged(t, d, "s1", "10.0.0.1", "pow", "t13d_a", 5000, 800, 10)
	insReuseJudged(t, d, "s1", "10.0.0.2", "pow", "t13d_b", 1200, 1200, 10)
	// Rows from before the column existed: judged 0, the whole still shown.
	insReuseJudged(t, d, "s1", "10.0.0.3", "pow", "t13d_c", 300, 0, 10)

	rows, err := CookieReuseTopIPs(context.Background(), d, "s1", "pow", nil, 24, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].IP != "10.0.0.2" || rows[1].IP != "10.0.0.1" || rows[2].IP != "10.0.0.3" {
		t.Fatalf("order = %+v, want judged 1200, 800, 0", rows)
	}
	if rows[0].Judged != 1200 || rows[0].Requests != 1200 || rows[1].Judged != 800 || rows[1].Requests != 5000 || rows[2].Judged != 0 || rows[2].Requests != 300 {
		t.Fatalf("counts = %+v", rows)
	}
}

// TestFillReuseCapHits: beside the judged count, how often the cap raised a
// CAPTCHA for the address in the window -- the serve rows with force_reason
// reuse_limit -- and nothing for the other reasons or other addresses.
func TestFillReuseCapHits(t *testing.T) {
	d := reuseTestDB(t)
	ctx := context.Background()
	// A minute back: the window's end is the query's second, and a row of
	// that same second, with its milliseconds, sorts past it.
	serve := func(ip, reason string) {
		if err := events.Insert(ctx, d, &events.Event{
			Site: "s1", IPPacked: events.PackIP(ip), Phase: "serve",
			Payload:    map[string]any{"force_reason": reason},
			OccurredAt: time.Now().Add(-time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	serve("10.0.0.1", "reuse_limit")
	serve("10.0.0.1", "reuse_limit")
	serve("10.0.0.1", "rate_limit")
	serve("10.0.0.2", "none")
	serve("10.0.0.9", "reuse_limit") // not in the ranking

	rows := []CookieReuseRow{{IP: "10.0.0.1"}, {IP: "10.0.0.2"}, {IP: "10.0.0.3"}}
	if err := FillReuseCapHits(ctx, d, "s1", nil, 24, rows); err != nil {
		t.Fatal(err)
	}
	if rows[0].Capped != 2 || rows[1].Capped != 0 || rows[2].Capped != 0 {
		t.Fatalf("capped = %d %d %d, want 2 0 0", rows[0].Capped, rows[1].Capped, rows[2].Capped)
	}
	if err := FillReuseCapHits(ctx, d, "s1", nil, 24, nil); err != nil {
		t.Fatalf("no rows: %v", err)
	}
}
