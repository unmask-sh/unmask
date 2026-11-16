package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The flusher says when the oldest event it keeps unwritten happened
// (db.OldestUnwritten), and the dashboard's time-cursor rollups do not fold
// that hour until it is written (review finding D9).  The dashboard's tests
// show it through a hold and across a stop; here the writes fail -- the
// database down, full -- and the events are kept the same way.  The failure
// is made as TestFlusherBoundsWhatItKeepsWhenWritesFail makes it.
func TestFlusherSaysWhatItKeepsWhileWritesFail(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "f.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	waitUntil := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); !cond(); {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	count := func() int {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if _, err := d.Exec(`ALTER TABLE unmask_event RENAME TO unmask_event_away`); err != nil {
		t.Fatal(err)
	}
	f := NewFlusher(d, 10, 50)
	defer f.Stop()
	at := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	for i := 0; i < 3; i++ {
		f.Submit(&Event{Site: "s", IPPacked: []byte{10, 0, 0, byte(i)}, Phase: "serve", OccurredAt: at.Add(time.Duration(i) * time.Second)})
	}
	waitUntil("the flusher to say it keeps the events", func() bool {
		oldest, ok := d.OldestUnwritten(db.UnwrittenEvents)
		return ok && oldest.Equal(at)
	})

	if _, err := d.Exec(`ALTER TABLE unmask_event_away RENAME TO unmask_event`); err != nil {
		t.Fatal(err)
	}
	waitUntil("the kept events to be written", func() bool { return count() == 3 })
	waitUntil("the flusher to say it keeps none", func() bool {
		_, ok := d.OldestUnwritten(db.UnwrittenEvents)
		return !ok
	})
}

// The worker reads back what the last stop carried over as it starts, off
// the start's path: a large carry-over takes a while to read.  Until it has,
// the flusher cannot say how old the events it keeps are, and says the
// oldest there can be -- the daemon's first rollup pass runs meanwhile.  A
// named pipe stands in for a file that takes long to read: the read waits
// for the test to write it.
func TestFlusherKeepsEventsOfUnknownAgeUntilItHasReadTheCarryOver(t *testing.T) {
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
	path := filepath.Join(dir, HeldSpillFile)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no named pipe: %v", err)
	}
	at := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	b, err := json.Marshal([]*Event{{Site: "s", IPPacked: []byte{10, 0, 0, 1}, Phase: "serve", OccurredAt: at}})
	if err != nil {
		t.Fatal(err)
	}
	d.HoldWrites(true) // the carried event stays unwritten for the look
	f := NewFlusher(d, 10, 50)
	defer f.Stop()
	if got, ok := d.OldestUnwritten(db.UnwrittenEvents); !ok || got.Unix() != unwrittenUnknown {
		t.Errorf("before the carry-over is read: kept since %v (%v), want the oldest time there is", got, ok)
	}
	// The open waits for the worker's read and meets it; nothing before it
	// may end the test, or Stop would wait for a worker that waits on the
	// pipe.  From here on, closing this end ends that read, so Stop is
	// safe however the test ends.
	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if oldest, ok := d.OldestUnwritten(db.UnwrittenEvents); ok && oldest.Equal(at) {
			break
		}
		if time.Now().After(deadline) {
			oldest, ok := d.OldestUnwritten(db.UnwrittenEvents)
			t.Fatalf("after the carry-over is read: kept since %v (%v), want the carried event's %v", oldest, ok, at)
		}
	}
	d.HoldWrites(false)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, ok := d.OldestUnwritten(db.UnwrittenEvents); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the carried event was not written")
		}
	}
}
