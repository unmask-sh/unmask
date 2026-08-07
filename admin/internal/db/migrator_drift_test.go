package db

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestMigrationRecoversFromPredatingColumn: a migration must complete on a
// database that already carries part of its work.
//
// Three fleet nodes sat at version 24 with the ref_id column present -- a
// development binary had run an earlier form of the change -- and 0025 could
// then never apply: the ADD COLUMN failed on the duplicate, the failure
// aborted the file before CREATE INDEX ran, the version was never recorded,
// and every restart retried the same statement into the same error.  The
// index the migration exists for was missing the whole time, and nothing was
// ever going to create it.
//
// The runner now treats "already exists" as that statement being in effect
// and carries on, so the surviving statements run and the version records.
func TestMigrationRecoversFromPredatingColumn(t *testing.T) {
	path := t.TempDir() + "/s.sqlite"
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if err := Migrate(d); err != nil {
		t.Fatalf("initial migrate: %v", err)
	}

	// Reproduce the wedged fleet state: the migration that adds the index is
	// pending again while the column it also adds is already there.
	//
	// Everything from 25 up is removed, not just 25: the runner tracks one
	// current version (the max), so leaving a later row in place would make 25
	// look applied and this test would silently stop exercising anything.
	if _, err := d.Exec(`DELETE FROM schema_migrations WHERE version >= 25`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DROP INDEX idx_unmask_event_ref`); err != nil {
		t.Fatal(err)
	}

	if err := Migrate(d); err != nil {
		t.Fatalf("migrate over the drifted schema: %v", err)
	}

	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 25`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("version 25 not recorded after recovery (rows=%d)", n)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type='index' AND name='idx_unmask_event_ref'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("idx_unmask_event_ref still missing -- the statement after the duplicate never ran")
	}
}
