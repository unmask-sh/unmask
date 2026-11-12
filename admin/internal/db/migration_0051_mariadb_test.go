package db

import (
	"strings"
	"testing"
)

// TestMariaDB_CrawlerSiteHourly: migration 0051 on a live MariaDB.  The
// per-site crawler table is there with its columns in the order the readers
// name them, each with its comment; the site is part of the key; the
// (site, bucket_hour) index exists; the install-wide table has not gained a
// column; and the file run again changes nothing.  Skips unless
// UNMASK_TEST_MARIADB_HOST is set (= make test-mariadb).  Rows carry an hour of
// their own and are removed.
func TestMariaDB_CrawlerSiteHourly(t *testing.T) {
	conn, err := Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer conn.Close()
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cleanup := func() { _, _ = conn.Exec(`DELETE FROM unmask_crawler_site_hourly WHERE bucket_hour = 490000`) }
	cleanup()
	defer cleanup()

	columns := func(table string) []string {
		t.Helper()
		rows, err := conn.Query(`SELECT COLUMN_NAME, COLUMN_COMMENT FROM INFORMATION_SCHEMA.COLUMNS
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION`, table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var cols []string
		for rows.Next() {
			var name, comment string
			if err := rows.Scan(&name, &comment); err != nil {
				t.Fatal(err)
			}
			if comment == "" {
				t.Errorf("%s.%s has no comment", table, name)
			}
			cols = append(cols, name)
		}
		return cols
	}
	if got := strings.Join(columns("unmask_crawler_site_hourly"), ","); got != "bucket_hour,site,category,crawler,total,served,verified,named" {
		t.Errorf("unmask_crawler_site_hourly columns = %s", got)
	}
	if got := strings.Join(columns("unmask_crawler_detail_hourly"), ","); got != "bucket_hour,category,crawler,total,served" {
		t.Errorf("unmask_crawler_detail_hourly columns = %s: the migration must leave that table alone", got)
	}

	rows, err := conn.Query(`SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'unmask_crawler_site_hourly'
		  AND INDEX_NAME = 'PRIMARY' ORDER BY SEQ_IN_INDEX`)
	if err != nil {
		t.Fatal(err)
	}
	var key []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		key = append(key, c)
	}
	rows.Close()
	if got := strings.Join(key, ","); got != "bucket_hour,site,category,crawler" {
		t.Errorf("primary key = %s, want bucket_hour,site,category,crawler", got)
	}
	if has, err := hasIndexNamed(conn, "unmask_crawler_site_hourly", "idx_crawler_site_site_hour"); err != nil || !has {
		t.Errorf("idx_crawler_site_site_hour: has=%v err=%v", has, err)
	}

	ins := `INSERT INTO unmask_crawler_site_hourly (bucket_hour, site, category, crawler, total, served, verified, named)
		VALUES (490000, ?, 'search-engine', 'Googlebot', 100, 10, 80, 0)`
	for _, site := range []string{"a.example.com", "b.example.com"} {
		if _, err := conn.Exec(ins, site); err != nil {
			t.Fatalf("the same hour, category and crawler on site %s was refused: %v", site, err)
		}
	}
	if _, err := conn.Exec(ins, "a.example.com"); err == nil {
		t.Error("a second row for the same hour, site, category and crawler was accepted: the key does not hold")
	}

	// The file again over its own result.
	if _, err := conn.Exec(`DELETE FROM schema_migrations WHERE version = 51`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(conn); err != nil {
		t.Fatalf("0051 run again over its own result: %v", err)
	}
	var n, sum int
	if err := conn.QueryRow(`SELECT COUNT(*), COALESCE(SUM(total), 0) FROM unmask_crawler_site_hourly WHERE bucket_hour = 490000`).Scan(&n, &sum); err != nil {
		t.Fatal(err)
	}
	if n != 2 || sum != 200 {
		t.Errorf("after a second run: %d rows adding up to %d, want the 2 rows and 200", n, sum)
	}
}
