package db

import (
	"fmt"
	"testing"
	"time"
)

// fillRollup writes n rows into unmask_aggregate_hourly the way the
// aggregator does: hour by hour, a few kinds in each.
func fillRollup(t *testing.T, d *DB, n int) {
	t.Helper()
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO unmask_aggregate_hourly (bucket_hour, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, 1)`)
	if err != nil {
		t.Fatal(err)
	}
	kinds := []string{"fnl", "ckph", "ccph", "svk", "sa"}
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		hour := start.Add(time.Duration(i/10) * time.Hour).Format("2006-01-02 15")
		if _, err := stmt.Exec(hour, kinds[i%len(kinds)], fmt.Sprintf("k%d", i%10)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestApproxRowsOfATableWithoutAnID: the rollup tables are keyed by (hour,
// kind, key) and have no id, so a deferrable migration on one could not be
// sized -- and a migration that cannot be sized is applied at startup whatever
// it costs.  SQLite numbers the rows anyway, and a table filled forward and
// pruned from its old end leaves a contiguous run there, as ids do.
func TestApproxRowsOfATableWithoutAnID(t *testing.T) {
	d := migratedDB(t)
	if n, err := approxRows(d, "unmask_aggregate_hourly"); err != nil || n != 0 {
		t.Fatalf("empty table: rows %d, err %v; want 0, nil", n, err)
	}
	fillRollup(t, d, 900)
	if n, err := approxRows(d, "unmask_aggregate_hourly"); err != nil || n != 900 {
		t.Fatalf("rows %d, err %v; want the 900 the table holds", n, err)
	}
	// The hourly prune takes the oldest hours.
	if _, err := d.Exec(`DELETE FROM unmask_aggregate_hourly WHERE bucket_hour < '2026-09-02 00'`); err != nil {
		t.Fatal(err)
	}
	var left int64
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_aggregate_hourly`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if n, err := approxRows(d, "unmask_aggregate_hourly"); err != nil || n != left || left == 0 || left == 900 {
		t.Fatalf("after a prune: rows %d, err %v; want the %d left", n, err, left)
	}
	// A table with neither an id nor a rowid cannot be sized; the caller then
	// applies the migration instead of guessing.
	if _, err := d.Exec(`CREATE TABLE no_rowid (k TEXT PRIMARY KEY) WITHOUT ROWID`); err != nil {
		t.Fatal(err)
	}
	if _, err := approxRows(d, "no_rowid"); err == nil {
		t.Error("a WITHOUT ROWID table was sized; want an error")
	}
}

// TestRollupKindIndexWaitsForTheOperatorOnALargeTable: 0034 builds an index
// over the hourly rollup.  On most installs that is a second at startup; on
// one whose rollup is large it is left for the operator like the fingerprint
// index, with the row count the estimate was made from.
func TestRollupKindIndexWaitsForTheOperatorOnALargeTable(t *testing.T) {
	const index = "idx_unmask_aggregate_hourly_kind"
	d := migratedDB(t)
	if !hasIndexNow(t, d, index) {
		t.Fatalf("a migrated database has no %s", index)
	}
	// As an install upgrading across 0034 is: the rollup filled, the index
	// not built, the version not recorded.
	fillRollup(t, d, 600)
	for _, q := range []string{`DROP INDEX ` + index, `DELETE FROM schema_migrations WHERE version = 34`} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}

	res, err := MigrateWith(d, MigrateOptions{Defer: true, DeferOver: time.Millisecond, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(res.Deferred); got != "0034_aggregate_hourly_kind_index" {
		t.Fatalf("deferred = %q, want the rollup index", got)
	}
	p := res.Deferred[0]
	if p.Rows != 600 || len(p.Indexes) != 1 || p.Indexes[0] != index {
		t.Errorf("planned %v over %d rows, want %s over 600", p.Indexes, p.Rows, index)
	}
	if p.EstLow <= 0 || p.EstHigh <= p.EstLow {
		t.Errorf("estimate %v..%v is not a range", p.EstLow, p.EstHigh)
	}
	if hasIndexNow(t, d, index) {
		t.Fatal("the index was built although the migration was left for the operator")
	}

	// A small table is built at startup: the same database with the default
	// threshold has nothing left over.
	res, err = MigrateWith(d, MigrateOptions{Defer: true, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deferred) != 0 || len(res.Applied) != 1 || res.Applied[0].Name != "0034_aggregate_hourly_kind_index" {
		t.Fatalf("600 rows with the default threshold: deferred %q, applied %v; want it applied", names(res.Deferred), res.Applied)
	}
	if !hasIndexNow(t, d, index) {
		t.Fatal("0034 was applied and the index is not there")
	}
}
