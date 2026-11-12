package nginxlog

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// mariadbReader opens the MariaDB the test environment names (`make
// test-mariadb`), migrates it and returns a Reader on it; skipped without one.
func mariadbReader(t *testing.T) (*Reader, *db.DB) {
	t.Helper()
	host := os.Getenv("UNMASK_TEST_MARIADB_HOST")
	if host == "" {
		t.Skip("UNMASK_TEST_MARIADB_HOST not set; run `make test-mariadb` for a containerized MariaDB")
	}
	port := 3306
	if p := os.Getenv("UNMASK_TEST_MARIADB_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	envOr := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	d, err := db.Open(settings.DB{Driver: string(db.DriverMariaDB), MariaDB: settings.MariaDB{
		Host: host, Port: port,
		User:     envOr("UNMASK_TEST_MARIADB_USER", "root"),
		Password: os.Getenv("UNMASK_TEST_MARIADB_PASSWORD"),
		Database: envOr("UNMASK_TEST_MARIADB_DATABASE", "unmask_test"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM unmask_pass_ip_day WHERE site = 'nginxlog-mariadb'`); err != nil {
		t.Fatal(err)
	}
	return &Reader{d: d, cookieIPBuckets: map[cookieIPKey]*cookieIPBucket{},
		passBuckets: map[passKey]*passBucket{}, passHours: map[passHourKey]int{}}, d
}

// TestMariaDB_PassIPUpsert: the pass-count upsert in MariaDB's dialect --
// the levels keep the larger (GREATEST), the deltas add up -- since a
// statement that fails here rolls back every aggregate in the flush, once a
// minute, for the whole life of the install.
func TestMariaDB_PassIPUpsert(t *testing.T) {
	r, d := mariadbReader(t)
	const site = "nginxlog-mariadb"
	now := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	r.bumpPassAt(site, "s1.example", "203.0.113.9", "t13d_a", "UA-A", "1785943030.pow2.aaaa.0", "pow", true, now)
	r.bumpPassAt(site, "s1.example", "203.0.113.9", "t13d_a", "UA-A", "1785943030.pow2.aaaa.0", "pow", true, now)
	r.bumpPassAt(site, "s1.example", "203.0.113.9", "t13d_b", "UA-B", "1785943031.pow2.bbbb.0", "pow", false, now)
	r.flushOnce(true)
	got, n := readPassRow(t, d, site)
	want := passRow{cookies: 2, ja4s: 2, cnt: 3, judged: 2, peak: 2, ja4: "t13d_b", ua: "UA-B"}
	if n != 1 || got != want {
		t.Fatalf("after the first flush: %d rows, %+v; want 1 row %+v", n, got, want)
	}
	// A restarted daemon with one pass in memory: the count holds, the
	// requests add up.
	r2 := &Reader{d: d, cookieIPBuckets: map[cookieIPKey]*cookieIPBucket{}}
	r2.bumpPassAt(site, "s1.example", "203.0.113.9", "t13d_a", "UA-A", "1785943032.pow2.cccc.0", "pow", true, now)
	r2.flushOnce(true)
	got, _ = readPassRow(t, d, site)
	want = passRow{cookies: 2, ja4s: 2, cnt: 4, judged: 3, peak: 2, ja4: "t13d_a", ua: "UA-A"}
	if got != want {
		t.Fatalf("after a restart: %+v, want %+v", got, want)
	}
}

// TestMariaDB_FlushTakesAUserAgentOfAnyBytes: a User-Agent that is not
// UTF-8, and one a cut at 255 bytes would end inside a character, are
// written -- and with them the rest of the minute's flush.  MariaDB refuses
// a string that is not UTF-8 ("Incorrect string value"), which rolls the
// whole transaction back; the rows return to memory and are tried again a
// minute later, the same value among them, so one such request stopped the
// per-minute tables until the daemon was restarted.  In forward-auth mode
// the value is the request's own header.
func TestMariaDB_FlushTakesAUserAgentOfAnyBytes(t *testing.T) {
	r, d := mariadbReader(t)
	const site = "nginxlog-mariadb-ua"
	for _, q := range []string{
		`DELETE FROM unmask_cookie_ip_minute WHERE site = '` + site + `'`,
		`DELETE FROM unmask_pass_ip_day WHERE site = '` + site + `'`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	uas := map[string]string{
		"203.0.113.21": "curl/8\xff\xfe.0",                              // not UTF-8
		"203.0.113.22": strings.Repeat("a", 254) + "あいう",                // a character across byte 255
		"203.0.113.23": "Mozilla/5.0 (plain)",                           // rides in the same flush
		"203.0.113.24": strings.Repeat("\xe3\x81", 200),                 // nothing but halves of characters
		"203.0.113.25": "Mozilla/5.0 " + strings.Repeat("あ", 300) + "z", // wide characters past the width
	}
	now := time.Now()
	for ip, ua := range uas {
		r.BumpCookieIP(site, ip, strings.Repeat("j", 64), ua, "pow")
		r.bumpPassAt(site, "s1.example", ip, strings.Repeat("j", 64), ua, "1785943030.pow2.aaaa.0", "pow", true, now)
	}
	r.flushOnce(true)
	for _, table := range []string{"unmask_cookie_ip_minute", "unmask_pass_ip_day"} {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE site = '` + site + `'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != len(uas) {
			t.Errorf("%s: %d of the flush's %d rows were written", table, n, len(uas))
		}
	}
	var plain string
	if err := d.QueryRow(`SELECT ua FROM unmask_cookie_ip_minute WHERE site = '` + site + `' AND ua LIKE 'Mozilla/5.0 (plain)'`).Scan(&plain); err != nil {
		t.Errorf("the plain User-Agent that rode in the same flush was not written: %v", err)
	}
}
