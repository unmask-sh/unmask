package nginxlog

import (
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// passReader is cookieIPReader with the pass-count maps.
func passReader(t *testing.T) (*Reader, *db.DB) {
	t.Helper()
	r, d := cookieIPReader(t)
	r.passBuckets = map[passKey]*passBucket{}
	r.passHours = map[passHourKey]int{}
	return r, d
}

type passRow struct {
	cookies, ja4s, cnt, judged, peak int
	ja4, ua                          string
}

func readPassRow(t *testing.T, d *db.DB, site string) (passRow, int) {
	t.Helper()
	rows, err := d.Query(`SELECT cookies, ja4s, cnt, judged, peak_hour, ja4, ua FROM unmask_pass_ip_day WHERE site = ?`, site)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out passRow
	n := 0
	for rows.Next() {
		n++
		if err := rows.Scan(&out.cookies, &out.ja4s, &out.cnt, &out.judged, &out.peak, &out.ja4, &out.ua); err != nil {
			t.Fatal(err)
		}
	}
	return out, n
}

// TestParseBVField: the line carries the pass cookie ahead of the UA, and a
// line from a configuration without the field still parses with none.
func TestParseBVField(t *testing.T) {
	r := &Reader{}
	head := "<134>1761700000.123 site=s1.example kind=pow fc=0 hp=0 ip=203.0.113.9 ja4=t13d_a hpuri= bp=0 scheme=https cr= pv=0 sb=0 sfs= sfd= rh="
	p, ok := r.parse(head + " bv=1785943030.pow2.2ni9.2~1785943000.9993339aa811854e.captcha ua=Mozilla/5.0 (X11) pass-test")
	if !ok {
		t.Fatal("the line with bv= did not parse")
	}
	if p.bv != "1785943030.pow2.2ni9.2~1785943000.9993339aa811854e.captcha" {
		t.Errorf("bv = %q", p.bv)
	}
	if p.ua != "Mozilla/5.0 (X11) pass-test" || p.kind != "pow" || p.ip != "203.0.113.9" {
		t.Errorf("the fields around bv= moved: ua=%q kind=%q ip=%q", p.ua, p.kind, p.ip)
	}
	p, ok = r.parse(head + " ua=Mozilla/5.0 (X11) pass-test")
	if !ok || p.bv != "" || p.ua != "Mozilla/5.0 (X11) pass-test" {
		t.Errorf("a line without bv=: ok=%v bv=%q ua=%q", ok, p.bv, p.ua)
	}
	// An empty field, as nginx logs a request without a verified cookie.
	p, ok = r.parse(head + " bv= ua=curl/8.0")
	if !ok || p.bv != "" || p.ua != "curl/8.0" {
		t.Errorf("a line with an empty bv=: ok=%v bv=%q ua=%q", ok, p.bv, p.ua)
	}
}

// TestPassCountsDistinctCookiesAndPeak: an address's day counts the distinct
// passes it presented and the busiest hour of one of them, with the requests
// and the judged requests beside; what is not a verified pass is not counted;
// the row keeps the levels across flushes and a restart, and accumulates the
// deltas.
func TestPassCountsDistinctCookiesAndPeak(t *testing.T) {
	r, d := passReader(t)
	// A day well in the past: the flush sweeps the hourly counters by the
	// wall clock, and the bucket of a past day stays as long as it has
	// something to write (the deltas below arrive before any flush that
	// could drop it clean).
	now := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	const a, b = "1785943030.pow2.aaaa.0", "1785943031.pow2.bbbb.0"

	for i := 0; i < 3; i++ {
		r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", a, "pow", true, now)
	}
	// A static file on the same pass: counted in the whole, not judged, and
	// not the peak.
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", a, "pow", false, now)
	// A second pass, with another fingerprint.
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_b", "UA-B", b, "pow", true, now)
	// Not a verified pass: no kind, no cookie, no address.
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_c", "UA-C", a, "", true, now)
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_c", "UA-C", "", "pow", true, now)
	r.bumpPassAt("s1", "s1.example", "", "t13d_c", "UA-C", a, "pow", true, now)

	r.flushOnce(true)
	got, n := readPassRow(t, d, "s1")
	if n != 1 {
		t.Fatalf("%d rows for the day, want 1", n)
	}
	want := passRow{cookies: 2, ja4s: 2, cnt: 5, judged: 4, peak: 3, ja4: "t13d_b", ua: "UA-B"}
	if got != want {
		t.Fatalf("after the first flush: %+v, want %+v", got, want)
	}

	// The next hour: the first pass again, twice -- below the peak so far;
	// the deltas accumulate and the levels hold.
	later := now.Add(time.Hour)
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", a, "pow", true, later)
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", a, "pow", true, later)
	r.flushOnce(true)
	got, _ = readPassRow(t, d, "s1")
	want = passRow{cookies: 2, ja4s: 2, cnt: 7, judged: 6, peak: 3, ja4: "t13d_a", ua: "UA-A"}
	if got != want {
		t.Fatalf("after the second flush: %+v, want %+v", got, want)
	}

	// A restart forgets the day's set: a fresh reader seeing one pass must
	// not lower the stored count, and its requests still add up.
	r2 := &Reader{d: d, cookieIPBuckets: map[cookieIPKey]*cookieIPBucket{}}
	r2.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", "1785943032.pow2.cccc.0", "pow", true, later)
	r2.flushOnce(true)
	got, _ = readPassRow(t, d, "s1")
	want = passRow{cookies: 2, ja4s: 2, cnt: 8, judged: 7, peak: 3, ja4: "t13d_a", ua: "UA-A"}
	if got != want {
		t.Fatalf("after a restart: %+v, want %+v", got, want)
	}
}

// TestPassBucketOfAPastDayIsDropped: once a past day's bucket has nothing
// left to write it leaves memory, and the passes it held leave the count
// that bounds them.
func TestPassBucketOfAPastDayIsDropped(t *testing.T) {
	r, _ := passReader(t)
	now := time.Date(2026, 10, 29, 23, 50, 0, 0, time.UTC)
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", "1785943030.pow2.aaaa.0", "pow", true, now)
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", "1785943031.pow2.bbbb.0", "pow", true, now)
	r.flushOnce(true)
	r.mu.Lock()
	if len(r.passBuckets) != 1 || r.passIDs != 2 {
		t.Fatalf("after the flush: %d buckets, %d passes held; want the day's bucket with its 2 passes", len(r.passBuckets), r.passIDs)
	}
	if len(r.passHours) != 2 {
		t.Fatalf("%d hourly counters, want one per pass in the hour", len(r.passHours))
	}
	// The next day's flush: the written bucket of the day before goes, and
	// the hourly counters of the past hour with it.
	entries := r.collectPassLocked(now.Add(time.Hour))
	if len(entries) != 0 || len(r.passBuckets) != 0 || r.passIDs != 0 {
		t.Errorf("the past day's bucket: %d entries, %d buckets, %d passes held; want none", len(entries), len(r.passBuckets), r.passIDs)
	}
	if len(r.passHours) != 0 {
		t.Errorf("%d hourly counters of a past hour survived the flush", len(r.passHours))
	}
	r.mu.Unlock()
}

// TestPassMatcherNamesThePass: with a matcher, the pass is the entry that
// verified -- two cookie values carrying the same entry among junk are one
// pass -- and a value the matcher cannot name is named by itself.
func TestPassMatcherNamesThePass(t *testing.T) {
	r, d := passReader(t)
	r.SetPassMatcher(func(value, ip, host string) string {
		if ip != "203.0.113.9" || host != "s1.example" {
			t.Errorf("the matcher was asked about ip=%q host=%q", ip, host)
		}
		switch value {
		case "A~junk1", "A~junk2", "A":
			return "A"
		case "B~A":
			return "B"
		}
		return ""
	})
	now := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	for _, v := range []string{"A~junk1", "A~junk2", "A", "B~A", "Z"} {
		r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", v, "pow", true, now)
	}
	r.flushOnce(true)
	got, _ := readPassRow(t, d, "s1")
	if got.cookies != 3 {
		t.Errorf("cookies = %d, want 3 (A, B and the unnamed Z)", got.cookies)
	}
	if got.peak != 3 {
		t.Errorf("peak = %d, want 3 (the three requests on A in the hour)", got.peak)
	}
}

// TestPassFlushPutsTheDeltasBackOnFailure: a flush that fails leaves the
// requests it carried for the next one, and the levels never left memory.
func TestPassFlushPutsTheDeltasBackOnFailure(t *testing.T) {
	r, d := passReader(t)
	now := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", "1785943030.pow2.aaaa.0", "pow", true, now)
	r.bumpPassAt("s1", "s1.example", "203.0.113.9", "t13d_a", "UA-A", "1785943031.pow2.bbbb.0", "pow", true, now)
	if _, err := d.Exec(`DROP TABLE unmask_pass_ip_day`); err != nil {
		t.Fatal(err)
	}
	r.flushOnce(true)
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.passBuckets[passKey{day: now.Unix() / 86400, site: "s1", ip: "203.0.113.9"}]
	if b == nil {
		t.Fatal("the bucket is gone after the failed flush")
	}
	if b.cnt != 2 || b.judged != 2 || !b.dirty || len(b.ids) != 2 || b.peak != 1 {
		t.Errorf("after the failed flush: cnt=%d judged=%d dirty=%v passes=%d peak=%d; want the two requests back, dirty, levels kept",
			b.cnt, b.judged, b.dirty, len(b.ids), b.peak)
	}
}
