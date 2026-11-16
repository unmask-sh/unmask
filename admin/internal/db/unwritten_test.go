package db

import (
	"testing"
	"time"
)

// OldestUnwritten is the oldest of what the writers of one source keep: a
// writer that keeps nothing does not count, a writer of another source does
// not either, and with none keeping anything there is no time at all.
func TestOldestUnwrittenIsTheOldestOfTheSourcesWriters(t *testing.T) {
	d := &DB{}
	if at, ok := d.OldestUnwritten(UnwrittenEvents); ok {
		t.Fatalf("no writer registered, and a row is kept since %v", at)
	}
	var none, older, newer, other bool
	t0 := time.Unix(1_800_000_000, 0)
	d.KeepsUnwritten(UnwrittenEvents, func() (time.Time, bool) { return time.Time{}, none })
	d.KeepsUnwritten(UnwrittenEvents, func() (time.Time, bool) { return t0.Add(time.Hour), newer })
	d.KeepsUnwritten(UnwrittenEvents, func() (time.Time, bool) { return t0, older })
	d.KeepsUnwritten(UnwrittenAccessLog, func() (time.Time, bool) { return t0.Add(-time.Hour), other })
	if at, ok := d.OldestUnwritten(UnwrittenEvents); ok {
		t.Fatalf("no writer keeps a row, and one is kept since %v", at)
	}
	newer = true
	if at, ok := d.OldestUnwritten(UnwrittenEvents); !ok || !at.Equal(t0.Add(time.Hour)) {
		t.Fatalf("one writer keeps rows since %v: got %v, %v", t0.Add(time.Hour), at, ok)
	}
	older = true
	if at, ok := d.OldestUnwritten(UnwrittenEvents); !ok || !at.Equal(t0) {
		t.Fatalf("the oldest row is from %v: got %v, %v", t0, at, ok)
	}
	other = true
	if at, ok := d.OldestUnwritten(UnwrittenEvents); !ok || !at.Equal(t0) {
		t.Fatalf("an older row of the access log holds the events back: got %v, %v, want %v", at, ok, t0)
	}
	if at, ok := d.OldestUnwritten(UnwrittenAccessLog); !ok || !at.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("the access log's own row is from %v: got %v, %v", t0.Add(-time.Hour), at, ok)
	}
	var nilDB *DB
	nilDB.KeepsUnwritten(UnwrittenEvents, func() (time.Time, bool) { return t0, true })
	if _, ok := nilDB.OldestUnwritten(UnwrittenEvents); ok {
		t.Fatal("a nil database keeps rows")
	}
}
