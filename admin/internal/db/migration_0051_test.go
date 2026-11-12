package db

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestMigration0051AddsThePerSiteCrawlerTable: 0051 creates the per-site
// crawler table beside the install-wide one and leaves that one alone.  The
// site is part of the new table's key, a site's rows can be sought by the
// (site, bucket_hour) index, and the file run again changes nothing.
func TestMigration0051AddsThePerSiteCrawlerTable(t *testing.T) {
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := Migrate(d); err != nil {
		t.Fatal(err)
	}
	const table = "unmask_crawler_site_hourly"
	for _, col := range []string{"bucket_hour", "site", "category", "crawler", "total", "served", "verified", "named"} {
		if has, err := hasColumn(d, table, col); err != nil || !has {
			t.Errorf("column %s: has=%v err=%v", col, has, err)
		}
	}
	if has, err := hasIndexNamed(d, table, "idx_crawler_site_site_hour"); err != nil || !has {
		t.Errorf("idx_crawler_site_site_hour: has=%v err=%v", has, err)
	}

	// The site is part of the key: the same hour, category and crawler on two
	// sites are two rows, and the same site twice is refused.
	ins := `INSERT INTO unmask_crawler_site_hourly (bucket_hour, site, category, crawler, total, served, verified, named)
		VALUES (490000, ?, 'search-engine', 'Googlebot', 100, 10, 80, 0)`
	for _, site := range []string{"a.example.com", "b.example.com"} {
		if _, err := d.Exec(ins, site); err != nil {
			t.Fatalf("the same hour, category and crawler on site %s was refused: %v", site, err)
		}
	}
	if _, err := d.Exec(ins, "a.example.com"); err == nil {
		t.Error("a second row for the same hour, site, category and crawler was accepted: the key does not hold")
	}

	// The install-wide table is as 0021 left it, so the statement a daemon
	// from before this migration writes it with still finds its conflict
	// target: an install rolled back to the older binary goes on counting.
	if has, err := hasColumn(d, "unmask_crawler_detail_hourly", "site"); err != nil || has {
		t.Errorf("unmask_crawler_detail_hourly has a site column (has=%v err=%v): the migration must leave that table alone", has, err)
	}
	const older = `INSERT INTO unmask_crawler_detail_hourly (bucket_hour, category, crawler, total, served)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(bucket_hour, category, crawler) DO UPDATE SET
			total = total + excluded.total, served = served + excluded.served`
	for i := 0; i < 2; i++ {
		if _, err := d.Exec(older, 490000, "search-engine", "Googlebot", 150, 10); err != nil {
			t.Fatalf("the install-wide upsert of an older daemon: %v", err)
		}
	}
	var total int
	if err := d.QueryRow(`SELECT total FROM unmask_crawler_detail_hourly WHERE bucket_hour = 490000`).Scan(&total); err != nil || total != 300 {
		t.Errorf("install-wide row after two upserts: total=%d err=%v, want 300", total, err)
	}

	// The file again over its own result: nothing rebuilt, nothing lost.
	if _, err := d.Exec(`DELETE FROM schema_migrations WHERE version = 51`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(d); err != nil {
		t.Fatalf("0051 run again over its own result: %v", err)
	}
	var rows, sum, recorded int
	if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(total), 0) FROM unmask_crawler_site_hourly`).Scan(&rows, &sum); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || sum != 200 {
		t.Errorf("after a second run: %d rows adding up to %d, want the 2 rows and 200", rows, sum)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 51`).Scan(&recorded); err != nil || recorded != 1 {
		t.Errorf("version 51 is recorded %d times (err %v), want once", recorded, err)
	}
}
