package db

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

// TestMariaDB_RollupKindIndex: migration 0034 on a live MariaDB.  The index
// is there with its columns in the order the rollup reads need, the optimizer
// can use it for the shape the 30-day cards send, and a table without an id
// column is sized from the catalog.  Skips unless UNMASK_TEST_MARIADB_HOST is
// set (= make test-mariadb).  Rows carry a kind of their own and are removed.
func TestMariaDB_RollupKindIndex(t *testing.T) {
	conn, err := Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	const kind = "mdbt"
	cleanup := func() { _, _ = conn.Exec(`DELETE FROM unmask_aggregate_hourly WHERE bucket_kind LIKE 'mdbt%'`) }
	cleanup()
	defer cleanup()

	rows, err := conn.Query(`SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'unmask_aggregate_hourly'
		  AND INDEX_NAME = 'idx_unmask_aggregate_hourly_kind' ORDER BY SEQ_IN_INDEX`)
	if err != nil {
		t.Fatal(err)
	}
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	rows.Close()
	if got := strings.Join(cols, ","); got != "bucket_kind,bucket_hour,bucket_key,cnt" {
		t.Fatalf("index columns = %q, want bucket_kind,bucket_hour,bucket_key,cnt", got)
	}

	// The card's own kind among others, hour by hour.
	tx, err := conn.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for h := 0; h < 200; h++ {
		hour := fmt.Sprintf("2026-09-%02d %02d", 1+h/24, h%24)
		for i := 0; i < 12; i++ {
			k := kind
			if i >= 2 {
				k = fmt.Sprintf("%s%d", kind, i%4)
			}
			if _, err := tx.Exec(`INSERT INTO unmask_aggregate_hourly (bucket_hour, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, 1)`,
				hour, k, fmt.Sprintf("k%d", i)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`ANALYZE TABLE unmask_aggregate_hourly`); err != nil {
		t.Fatal(err)
	}

	// Sized without an id column: the catalog's count, which ANALYZE has just
	// brought up to date -- approximate, so only its order of magnitude is held.
	n, err := approxRows(conn, "unmask_aggregate_hourly")
	if err != nil {
		t.Fatalf("approxRows: %v", err)
	}
	if n < 1200 || n > 24000 {
		t.Errorf("approxRows = %d for a table holding at least the 2,400 rows just written", n)
	}

	// The read the 30-day cards send can be served from the index.
	var id, selectType, table, typ, possible, key, keyLen, ref, extra sql.NullString
	var rowsEst sql.NullString
	if err := conn.QueryRow(`EXPLAIN SELECT bucket_hour, bucket_key, cnt FROM unmask_aggregate_hourly
		WHERE bucket_kind = ? AND bucket_hour >= ? AND bucket_hour <= ?`, kind, "2026-09-01 00", "2026-09-09 23").
		Scan(&id, &selectType, &table, &typ, &possible, &key, &keyLen, &ref, &rowsEst, &extra); err != nil {
		t.Fatalf("explain: %v", err)
	}
	if !strings.Contains(possible.String, "idx_unmask_aggregate_hourly_kind") {
		t.Errorf("possible_keys = %q: the optimizer cannot use the kind index for the cards' read", possible.String)
	}
	t.Logf("plan: key=%s rows=%s extra=%s", key.String, rowsEst.String, extra.String)
}
