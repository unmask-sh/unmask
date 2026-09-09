package db

import (
	"context"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The maintenance open keeps SQLite's temporary storage on disk, in the
// database's own directory, on a single connection; the daemon's open keeps
// it in memory.  A VACUUM or an index build over a large table is a copy of
// its result in the temp store, so the daemon's setting would be an
// out-of-memory kill for `unmask db-prune` on the databases it exists for.
func TestOpenMaintenanceKeepsTempOnDisk(t *testing.T) {
	dir := t.TempDir()
	cfg := settings.DB{Driver: "sqlite", SQLitePath: dir + "/unmask.sqlite"}

	m, err := OpenMaintenance(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	var store int
	if err := m.QueryRow(`PRAGMA temp_store`).Scan(&store); err != nil {
		t.Fatal(err)
	}
	if store != 1 {
		t.Errorf("maintenance temp_store = %d, want 1 (FILE)", store)
	}
	var tdir string
	if err := m.QueryRow(`PRAGMA temp_store_directory`).Scan(&tdir); err != nil {
		t.Fatal(err)
	}
	if tdir != dir {
		t.Errorf("maintenance temp_store_directory = %q, want the database directory %q", tdir, dir)
	}
	if got := m.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("maintenance pool = %d connections, want 1", got)
	}

	// The page accounting and the free space it is measured against.
	sp, err := m.Space(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sp.PageSize <= 0 || sp.LiveBytes <= 0 || sp.FileBytes < sp.LiveBytes {
		t.Errorf("space accounting: %+v", sp)
	}
	if free, err := DirFree(dir); err != nil || free <= 0 {
		t.Errorf("DirFree(%s) = %d, %v", dir, free, err)
	}
	m.Close()

	d, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := d.QueryRow(`PRAGMA temp_store`).Scan(&store); err != nil {
		t.Fatal(err)
	}
	if store != 2 {
		t.Errorf("daemon temp_store = %d, want 2 (MEMORY)", store)
	}
	if got := d.Stats().MaxOpenConnections; got < 2 {
		t.Errorf("daemon pool = %d connections, want a pool", got)
	}
}
