package nginxlog

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestMariaDB_LetThroughFlush: the let-through upserts in MariaDB's dialect,
// with values as wide as the line can carry.  MariaDB's strict mode refuses
// a value wider than its column, and with it every aggregate of the flush,
// once a minute, for the life of the install -- so the widths the reader cuts
// to are held against the real columns here, and the deltas of two flushes
// against the rows.
func TestMariaDB_LetThroughFlush(t *testing.T) {
	r, d := mariadbReader(t)
	r.letBuckets = map[letKey]*letBucket{}
	const site = "nginxlog-mariadb-let"
	for _, tb := range []string{"unmask_let_hourly", "unmask_let_ip_hourly"} {
		if _, err := d.Exec(`DELETE FROM `+tb+` WHERE site = ?`, site); err != nil {
			t.Fatal(err)
		}
	}
	r.SetLetThroughDetail(func(string) string { return "list:" + strings.Repeat("範", 100) }, nil)
	// Two stamps a minute and a half apart, in one hour, the later of them
	// now: the reader holds a line's time to this hour and the last, so a
	// stamp ahead of the clock would be read as now.
	later := time.Now().Unix()
	ts := later - 90
	if ts/3600 != later/3600 {
		ts = later - later%3600
	}
	wide := func(ip, why, lp, ua string) {
		t.Helper()
		letFeed(t, r, letLine(ts, site, "", ip, why, lp, ua))
	}
	wide("203.0.113.9", LetIP, "/"+strings.Repeat("p", 400), strings.Repeat("ü", 400))
	wide("2001:db8::9", LetNone, "/x", "ua")
	wide("203.0.113.9", strings.Repeat("z", 40), "/q", "ua") // a ground from a newer configuration
	letFeed(t, r, letLine(ts, site, "captcha", "203.0.113.10", LetCookie, "", "ua"))
	r.flushOnce(true)

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := d.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM unmask_let_hourly WHERE site = ?`, site); n != 4 {
		t.Fatalf("%d total rows after the first flush, want 4 -- a row refused takes the whole flush with it", n)
	}
	if n := count(`SELECT COUNT(*) FROM unmask_let_ip_hourly WHERE site = ?`, site); n != 3 {
		t.Fatalf("%d address rows after the first flush, want 3 (a pass cookie is not listed)", n)
	}
	if n := count(`SELECT CHAR_LENGTH(ua) FROM unmask_let_ip_hourly WHERE site = ? AND reason = ?`, site, LetIP); n != cookieIPUAMax {
		t.Errorf("the User-Agent was stored at %d characters, want the column's %d", n, cookieIPUAMax)
	}
	if n := count(`SELECT CHAR_LENGTH(path) FROM unmask_let_ip_hourly WHERE site = ? AND reason = ?`, site, LetIP); n != letPathWidth {
		t.Errorf("the path was stored at %d characters, want the column's %d", n, letPathWidth)
	}
	if n := count(`SELECT CHAR_LENGTH(detail) FROM unmask_let_hourly WHERE site = ? AND reason = ?`, site, LetIP); n != letDetailWidth {
		t.Errorf("the detail was stored at %d characters, want the column's %d", n, letDetailWidth)
	}

	// A second flush: the deltas add up, first_seen keeps the earlier time
	// and last_seen takes the later.
	letFeed(t, r, letLine(later, site, "", "203.0.113.9", LetIP, "/second", "ua2"))
	r.flushOnce(true)
	var cnt int
	var path, ua string
	var span int
	if err := d.QueryRow(`SELECT cnt, path, ua, TIMESTAMPDIFF(SECOND, first_seen, last_seen)
		FROM unmask_let_ip_hourly WHERE site = ? AND reason = ?`, site, LetIP).Scan(&cnt, &path, &ua, &span); err != nil {
		t.Fatal(err)
	}
	if cnt != 2 || path != "/second" || ua != "ua2" {
		t.Errorf("after the second flush: cnt=%d path=%q ua=%q, want 2, /second, ua2", cnt, path, ua)
	}
	if want := int(later - ts); span != want {
		t.Errorf("first_seen to last_seen spans %d seconds, want %d", span, want)
	}
	if n := count(`SELECT cnt FROM unmask_let_hourly WHERE site = ? AND reason = ? AND bucket_hour = ?`, site, LetIP, later/3600); n != 2 {
		t.Errorf("the bucket counts %d requests after two flushes, want 2", n)
	}

	// A displaced address's row is deleted.
	r2, _ := mariadbReader(t)
	r2.letBuckets = map[letKey]*letBucket{}
	for i := 0; i < letAddrsPerKey; i++ {
		letFeed(t, r2, letLine(ts, site, "", fmt.Sprintf("10.20.%d.%d", i/250, i%250+1), LetName, "/x", "ua"))
	}
	r2.flushOnce(true)
	for i := 0; i < 5; i++ {
		letFeed(t, r2, letLine(ts, site, "", fmt.Sprintf("10.30.0.%d", i+1), LetName, "/x", "ua"))
	}
	r2.flushOnce(true)
	if n := count(`SELECT COUNT(*) FROM unmask_let_ip_hourly WHERE site = ? AND reason = ?`, site, LetName); n != letAddrsPerKey {
		t.Errorf("%d rows for one bucket after five addresses displaced five, want %d", n, letAddrsPerKey)
	}
}
