package events

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// While a schema update builds an index it holds SQLite's write lock, for
// minutes on a large table, and the challenge goes on serving all the while.
// Its events must not be thrown at the lock -- each flush would wait out the
// busy timeout, fail, and log, once a second for the length of the build --
// and must not be lost either: they are kept, and written when the lock is
// free.
func TestFlusherKeepsEventsWhileWritesAreHeld(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "f.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	f := NewFlusher(d, 10, 50)
	defer f.Stop()

	d.HoldWrites(true)
	// More than a batch, and more than one transaction's worth when written.
	const n = flushChunk + 250
	for i := 0; i < n; i++ {
		f.Submit(&Event{Site: "s", IPPacked: []byte{10, 0, 0, 1}, Phase: "serve"})
	}
	time.Sleep(400 * time.Millisecond)
	if got := count(); got != 0 {
		t.Fatalf("%d events were written while writes were held", got)
	}
	if f.DroppedCount() != 0 || f.DroppedOnErrorCount() != 0 {
		t.Fatalf("dropped %d (queue) + %d (error) of %d events that fit comfortably", f.DroppedCount(), f.DroppedOnErrorCount(), n)
	}

	d.HoldWrites(false)
	// Generous: under the race detector an insert costs milliseconds.
	deadline := time.Now().Add(60 * time.Second)
	for count() != n && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := count(); got != n {
		t.Fatalf("%d of %d kept events were written after the lock was released", got, n)
	}
	// And back to normal afterwards.
	f.Submit(&Event{Site: "s", IPPacked: []byte{10, 0, 0, 2}, Phase: "serve"})
	deadline = time.Now().Add(30 * time.Second)
	for count() != n+1 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := count(); got != n+1 {
		t.Fatalf("an event after the hold was not written (%d rows)", got)
	}
}
