package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The database's snapshot went beside the archive at the umask's 0644 -- a
// copy of every secret and address, readable by every local user -- and
// stayed there when a run stopped halfway.  The work happens in a 0700
// directory now, gone when the run ends, finished or not.
func TestBackupLeavesNoCopyBehind(t *testing.T) {
	config, database := migrateConfig(t, "")
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: database})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	d.Close()
	say := func(string, ...any) {}

	out := t.TempDir()
	path, err := runBackup(context.Background(), config, out, time.Date(2026, 11, 11, 23, 0, 0, 0, time.UTC), say)
	if err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(out)
	if len(ents) != 1 || ents[0].Name() != filepath.Base(path) {
		t.Errorf("left beside the archive: %v", ents)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the archive's mode: %v %v", st.Mode(), err)
	}

	// A run cancelled (Ctrl-C) leaves nothing at all.
	out2 := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runBackup(ctx, config, out2, time.Date(2026, 11, 11, 23, 1, 0, 0, time.UTC), say); err == nil {
		t.Error("a cancelled run reported an archive")
	}
	if ents, _ := os.ReadDir(out2); len(ents) != 0 {
		t.Errorf("a cancelled run left %v", ents)
	}
}
