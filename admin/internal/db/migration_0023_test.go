package db

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestMigration0023PreservesCaptchaHistory: 0023 rebuilds unmask_cookie_ip_minute
// to widen the primary key, which on SQLite means copying the table.  Existing
// rows are all CAPTCHA reuse by construction (bumpCookieIP recorded nothing
// else), so an upgrade must carry them over as kind='captcha' -- losing them
// would blank the card's ranking for 32 days with no way to rebuild it, since
// the source is a log stream that has already gone by.
func TestMigration0023PreservesCaptchaHistory(t *testing.T) {
	path := t.TempDir() + "/s.sqlite"
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Stand up the PRE-0023 shape and fill it, then let the migrator run over it
	// exactly as it would on an install upgrading from 0.1.12.
	if _, err := d.Exec(`CREATE TABLE unmask_cookie_ip_minute (
		bucket_min INTEGER NOT NULL, site VARCHAR(64) NOT NULL, ip BLOB NOT NULL,
		ja4 VARCHAR(40) NOT NULL DEFAULT '', ua VARCHAR(255) NOT NULL DEFAULT '',
		cnt INTEGER NOT NULL DEFAULT 0,
		last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (bucket_min, site, ip))`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`CREATE INDEX idx_cookie_ip_minute_site_min
		ON unmask_cookie_ip_minute(site, bucket_min)`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO unmask_cookie_ip_minute
		(bucket_min, site, ip, ja4, ua, cnt, last_seen)
		VALUES (100, 's1', x'01020304', 't13d_a', 'UA', 42, '2026-07-28 00:00:00.000')`); err != nil {
		t.Fatal(err)
	}

	if err := Migrate(d); err != nil {
		t.Fatalf("migrate over the pre-0023 table: %v", err)
	}

	var kind, ja4 string
	var cnt int
	if err := d.QueryRow(`SELECT kind, ja4, cnt FROM unmask_cookie_ip_minute`).
		Scan(&kind, &ja4, &cnt); err != nil {
		t.Fatalf("the pre-existing row did not survive the rebuild: %v", err)
	}
	if kind != "captcha" || ja4 != "t13d_a" || cnt != 42 {
		t.Errorf("carried-over row = kind %q ja4 %q cnt %d, want captcha/t13d_a/42", kind, ja4, cnt)
	}

	// The widened key has to be in force, or the two kinds collide on insert and
	// PoW volume lands on the CAPTCHA counter.
	if _, err := d.Exec(`INSERT INTO unmask_cookie_ip_minute
		(bucket_min, site, ip, kind, ja4, ua, cnt, last_seen)
		VALUES (100, 's1', x'01020304', 'pow', 't13d_b', 'UA', 7, '2026-07-28 00:00:00.000')`); err != nil {
		t.Fatalf("same IP-minute under a second kind was rejected: %v", err)
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_cookie_ip_minute`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("row count = %d, want 2 (kind is part of the primary key)", n)
	}

	// Re-running Migrate must be a no-op, not a second rebuild.
	if err := Migrate(d); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_cookie_ip_minute`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("row count after a second Migrate = %d, want 2", n)
	}
}

// TestMigration0023OnFreshInstall: on a new install migrate.go creates the
// post-0023 shape first and the numbered migrations then run over it, so 0023
// has to be harmless there -- its INSERT..SELECT supplies a literal 'captcha'
// and would flatten kinds if it ever ran against populated new-shape rows.
func TestMigration0023OnFreshInstall(t *testing.T) {
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := Migrate(d); err != nil {
		t.Fatal(err)
	}
	// Both kinds coexist, and both indexes exist under their final names.
	for _, kind := range []string{"captcha", "pow"} {
		if _, err := d.Exec(`INSERT INTO unmask_cookie_ip_minute
			(bucket_min, site, ip, kind, ja4, ua, cnt, last_seen)
			VALUES (100, 's1', x'01020304', ?, 't13d', 'UA', 1, '2026-07-28 00:00:00.000')`,
			kind); err != nil {
			t.Fatalf("insert kind=%s: %v", kind, err)
		}
	}
	for _, idx := range []string{"idx_cookie_ip_minute_site_min", "idx_cookie_ip_minute_kind_min"} {
		var name string
		if err := d.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&name); err != nil {
			t.Errorf("index %s missing after a fresh install: %v", idx, err)
		}
	}
}
