package events

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// panicky is a payload value whose marshalling panics: the shape of a bad
// row that, through 0.1.53, ended the flusher goroutine for the life of the
// process -- every event after it was queued, then dropped, with the daemon
// healthy to every probe.
type panicky struct{}

func (panicky) MarshalJSON() ([]byte, error) { panic("boom") }

// A row whose preparation panics is dropped on its own, counted, and the
// flusher goes on: the next event is written, and Stop still drains.
func TestFlusherSurvivesAPanickingRow(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "p.sqlite")})
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
	before := rowPanics.Load()
	f := NewFlusher(d, 1, 50) // a batch of one: every event is written at once
	f.Submit(&Event{Phase: "serve", IPPacked: PackIP("192.0.2.1"), Payload: map[string]any{"x": panicky{}}})
	f.Submit(&Event{Phase: "serve", IPPacked: PackIP("192.0.2.2")})
	deadline := time.Now().Add(30 * time.Second)
	for count() < 1 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := count(); got != 1 {
		t.Fatalf("%d rows written after the panicking row; want the good one", got)
	}
	if got := rowPanics.Load() - before; got != 1 {
		t.Errorf("rows dropped for a panic: %d, want 1", got)
	}
	if f.DroppedBadRowsCount() < 1 {
		t.Errorf("DroppedBadRowsCount = %d", f.DroppedBadRowsCount())
	}
	// The goroutine is alive: a third event is written, and Stop returns.
	f.Submit(&Event{Phase: "serve", IPPacked: PackIP("192.0.2.3")})
	stopped := make(chan struct{})
	go func() { f.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(30 * time.Second):
		t.Fatal("Stop did not return: the flusher goroutine is gone")
	}
	if got := count(); got != 2 {
		t.Errorf("%d rows after Stop, want 2", got)
	}
}
