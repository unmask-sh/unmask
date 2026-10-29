package nginxlog

import (
	"os"
	"strconv"
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
