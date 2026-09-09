package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The write-ahead log is measured by the file next to the database, and
// TrimWAL brings it to zero when nobody holds it: a PASSIVE checkpoint that
// covers the log, then a TRUNCATE.
func TestWALSizeAndTrim(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "w.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if got, want := d.WALPath(), filepath.Join(dir, "w.sqlite-wal"); got != want {
		t.Fatalf("WALPath = %q, want %q", got, want)
	}
	if _, err := d.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3000; i++ {
		if _, err := tx.Exec(`INSERT INTO t(v) VALUES (?)`, "0123456789abcdef0123456789abcdef0123456789abcdef"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if d.WALSize() == 0 {
		t.Fatal("a committed transaction leaves frames in the write-ahead log")
	}
	ctx := context.Background()
	cp, err := d.CheckpointWAL(ctx, "PASSIVE", 0)
	if err != nil || cp.Busy {
		t.Fatalf("passive checkpoint: %+v, %v", cp, err)
	}
	tr, err := d.TrimWAL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Truncated || tr.Blocked || tr.After != 0 {
		t.Errorf("with no reader on the log the trim truncates it: %+v", tr)
	}
	if _, err := d.CheckpointWAL(ctx, "SIDEWAYS", 0); err == nil {
		t.Error("an unknown mode is refused")
	}
}

// A reader on an older snapshot holds the log: the PASSIVE checkpoint stops
// at its mark, no TRUNCATE is attempted (nothing to gain, and it would hold
// writers off while it waited), and the trim returns promptly.  Once the
// reader is gone the next trim truncates.
func TestTrimWALHeldByReader(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "r.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	fill := func() {
		tx, err := d.Begin()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2000; i++ {
			if _, err := tx.Exec(`INSERT INTO t(v) VALUES (?)`, "0123456789abcdef0123456789abcdef"); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	fill()
	ctx := context.Background()
	if _, err := d.TrimWAL(ctx); err != nil {
		t.Fatal(err)
	}

	// A reader pinned to the snapshot before the next write.
	reader, err := d.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ExecContext(ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	fill()
	start := time.Now()
	tr, err := d.TrimWAL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Truncated || tr.After == 0 {
		t.Errorf("a reader on an older snapshot keeps the log: %+v", tr)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the trim must not wait on the reader, took %v", took)
	}
	if _, err := reader.ExecContext(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	reader.Close()
	if tr, err := d.TrimWAL(ctx); err != nil || !tr.Truncated || tr.After != 0 {
		t.Errorf("with the reader gone the trim truncates: %+v, %v", tr, err)
	}
}
