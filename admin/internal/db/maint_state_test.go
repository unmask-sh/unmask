package db

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The maintenance record round-trips through the migrated table and an
// upsert replaces, not duplicates.
func TestMaintStateRoundTrip(t *testing.T) {
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "m.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	var rec PruneRecord
	if ok, err := d.LoadMaintState(ctx, MaintEventsPrune, &rec); err != nil || ok {
		t.Fatalf("no record yet: ok=%v err=%v", ok, err)
	}
	if err := d.SaveMaintState(ctx, MaintEventsPrune, PruneRecord{StartedAt: 100, Retention: 7, Deleted: 5}); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveMaintState(ctx, MaintEventsPrune, PruneRecord{StartedAt: 100, CompletedAt: 160, Retention: 7, Deleted: 12, Chunks: 3, Err: ""}); err != nil {
		t.Fatal(err)
	}
	ok, err := d.LoadMaintState(ctx, MaintEventsPrune, &rec)
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if rec.CompletedAt != 160 || rec.Deleted != 12 || rec.Chunks != 3 {
		t.Errorf("got %+v, want the second write", rec)
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_maint_state`).Scan(&n); err != nil || n != 1 {
		t.Errorf("rows=%d err=%v, want one row per task", n, err)
	}
}
