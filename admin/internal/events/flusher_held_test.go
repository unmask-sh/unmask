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

// TestFlusherBoundsWhatItKeepsWhenWritesFail: when every insert fails -- the
// database down, full, read-only -- the flusher keeps a bounded backlog and
// drops the oldest.  Written a chunk at a time, a failing chunk used to return
// before the bound was applied, and the backlog grew for as long as the
// failure lasted: a bot flood during an outage was a way to run the daemon
// out of memory.
func TestFlusherBoundsWhatItKeepsWhenWritesFail(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "f.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	// Every insert fails.
	if _, err := d.Exec(`ALTER TABLE unmask_event RENAME TO unmask_event_away`); err != nil {
		t.Fatal(err)
	}
	f := NewFlusher(d, 500, 20)
	defer f.Stop()
	const n = 20000
	// Fed no faster than it takes them in, so that every event reaches the
	// backlog rather than the full queue's drop: the bound is what is tested.
	drained := func() {
		for deadline := time.Now().Add(30 * time.Second); len(f.ch) > 0 && time.Now().Before(deadline); {
			time.Sleep(5 * time.Millisecond)
		}
	}
	for i := 0; i < n; i++ {
		f.Submit(&Event{Site: "s", IPPacked: []byte{10, 0, 0, 1}, Phase: "serve"})
		if i%500 == 499 {
			drained()
		}
	}
	drained()
	time.Sleep(300 * time.Millisecond)
	if _, err := d.Exec(`ALTER TABLE unmask_event_away RENAME TO unmask_event`); err != nil {
		t.Fatal(err)
	}
	// Everything accounted for: written, dropped at the full queue, or
	// dropped by the bound -- and the bound did its part.
	var rows int
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if uint64(rows)+f.DroppedCount()+f.DroppedOnErrorCount() == n || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := uint64(rows) + f.DroppedCount() + f.DroppedOnErrorCount(); got != n {
		t.Fatalf("written %d + dropped %d (queue) + %d (bound) = %d, want all %d accounted for", rows, f.DroppedCount(), f.DroppedOnErrorCount(), got, n)
	}
	if f.DroppedCount() != 0 {
		t.Errorf("%d dropped at the queue; the test feeds slower than that", f.DroppedCount())
	}
	if f.DroppedOnErrorCount() < n-maxRetain-500 {
		t.Errorf("the bound dropped %d of %d: the backlog of failed writes was kept far past %d", f.DroppedOnErrorCount(), n, maxRetain)
	}
	// What was written after the failure: the bounded backlog and what was
	// still in the queue.
	if limit := maxRetain + flusherQueueSize + 500; rows > limit {
		t.Errorf("%d written after the failure, more than the backlog's bound and the queue hold (%d)", rows, limit)
	}
}

// TestFlusherWritesWhatItKeptAtShutdown: the daemon stops a schema update it
// started before its last flush, so the lock is free then, and the events kept
// while writes were held are written -- the last flush used to stand back for
// the hold too, and they were dropped without a word.
func TestFlusherWritesWhatItKeptAtShutdown(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "f.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	f := NewFlusher(d, 10, 50)
	d.HoldWrites(true)
	const n = 1200
	for i := 0; i < n; i++ {
		f.Submit(&Event{Site: "s", IPPacked: []byte{10, 0, 0, 1}, Phase: "serve"})
	}
	time.Sleep(300 * time.Millisecond)
	f.Stop()
	var rows int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != n {
		t.Errorf("%d of %d kept events written at shutdown", rows, n)
	}
}
