package events

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The daemon stops while a run from the shell still holds the database's
// writes: the final write fails, and the events kept meanwhile go to the
// data directory instead of away; the next start's flusher writes them
// (review finding S5).  The failure is made as TestFlusherBoundsWhatIt-
// KeepsWhenWritesFail makes it, the table renamed away.
func TestFlusherCarriesEventsAcrossAStopUnderAHold(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "f.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	SetSpillDir(dir)
	t.Cleanup(func() { SetSpillDir("") })
	count := func() int {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	f := NewFlusher(d, 10, 50)
	d.HoldWrites(true)
	const n = 37
	for i := 0; i < n; i++ {
		f.Submit(&Event{Site: "s", IPPacked: []byte{10, 0, 0, byte(i)}, Phase: "serve", OccurredAt: time.Now()})
	}
	time.Sleep(300 * time.Millisecond)
	// The lock still someone else's at the stop: every insert fails.
	if _, err := d.Exec(`ALTER TABLE unmask_event RENAME TO unmask_event_away`); err != nil {
		t.Fatal(err)
	}
	f.Stop()
	if _, err := d.Exec(`ALTER TABLE unmask_event_away RENAME TO unmask_event`); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 0 {
		t.Fatalf("%d events written under the hold", got)
	}
	if f.DroppedOnErrorCount() != 0 {
		t.Errorf("%d events counted dropped; they were carried over", f.DroppedOnErrorCount())
	}
	fi, err := os.Stat(filepath.Join(dir, HeldSpillFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the spill file: %v", err)
	}

	// The next start, the lock free.
	d.HoldWrites(false)
	f2 := NewFlusher(d, 10, 50)
	defer f2.Stop()
	deadline := time.Now().Add(30 * time.Second)
	for count() != n && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := count(); got != n {
		t.Fatalf("%d of %d carried-over events written after the start", got, n)
	}
	if _, err := os.Stat(filepath.Join(dir, HeldSpillFile)); !os.IsNotExist(err) {
		t.Errorf("the spill file is still there")
	}
}
