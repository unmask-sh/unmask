package events

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The rebuild's copy must not go through SQLite's sorter: with the date
// index and a sort, the sorter's working set is every kept row -- gigabytes
// on the databases the command exists for.  NOT INDEXED pins a rowid walk,
// which satisfies the ORDER BY as it goes.
func TestRebuildCopyIsSortFree(t *testing.T) {
	d := pruneTestDB(t)
	seedEvents(t, d, 50, time.Now().Add(-time.Hour))
	if _, err := d.Exec(`CREATE TABLE unmask_event_rebuild AS SELECT * FROM unmask_event WHERE 0`); err != nil {
		t.Fatal(err)
	}
	rows, err := d.Query(`EXPLAIN QUERY PLAN `+rebuildCopySQL, time.Now().Add(-24*time.Hour).UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	joined := strings.Join(plan, " | ")
	if strings.Contains(joined, "TEMP B-TREE") {
		t.Errorf("the copy sorts: %s", joined)
	}
	if !strings.Contains(joined, "SCAN unmask_event") || strings.Contains(joined, "USING INDEX") {
		t.Errorf("the copy must walk the table in rowid order, got: %s", joined)
	}
}

// The estimate sizes the new table before the copy: the rows the window
// keeps against the id span of the table.
func TestRebuildEstimate(t *testing.T) {
	d := pruneTestDB(t)
	seedEvents(t, d, 300, time.Now().Add(-20*24*time.Hour))
	seedEvents(t, d, 25, time.Now().Add(-time.Hour))
	kept, total, err := RebuildEstimate(context.Background(), d, 7)
	if err != nil {
		t.Fatal(err)
	}
	if kept != 25 || total != 325 {
		t.Errorf("estimate = %d kept of %d, want 25 of 325", kept, total)
	}
}

// The whole offline path on the maintenance connection: the temp store is
// on disk next to the file, the rebuild keeps the window, and the VACUUM
// that follows shrinks the file.
func TestRebuildUnderMaintenanceOpen(t *testing.T) {
	dir := t.TempDir()
	cfg := settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "m.sqlite")}
	seedConn := func() *db.DB {
		d, err := db.Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := seedConn()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	seedEvents(t, d, 2000, time.Now().Add(-20*24*time.Hour))
	seedEvents(t, d, 40, time.Now().Add(-time.Hour))
	d.Close()

	m, err := db.OpenMaintenance(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var store int
	if err := m.QueryRow(`PRAGMA temp_store`).Scan(&store); err != nil || store != 1 {
		t.Fatalf("temp_store = %d, %v; want 1 (FILE)", store, err)
	}
	ctx := context.Background()
	before, err := m.Space(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res, err := RebuildEvents(ctx, m, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kept != 40 {
		t.Errorf("kept %d rows, want 40", res.Kept)
	}
	if _, err := m.ExecContext(ctx, `VACUUM`); err != nil {
		t.Fatalf("vacuum on the maintenance connection: %v", err)
	}
	after, err := m.Space(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.FileBytes >= before.FileBytes {
		t.Errorf("VACUUM did not shrink the file: %d -> %d bytes", before.FileBytes, after.FileBytes)
	}
	var n int
	if err := m.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil || n != 40 {
		t.Errorf("rows after rebuild + vacuum = %d, %v; want 40", n, err)
	}
}
