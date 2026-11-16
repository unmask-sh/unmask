package db

import "time"

// Rows a writer keeps in memory before it writes them.
//
// The event flusher and the access-log reader collect rows for a moment
// before they write them -- and for as long as a hold of the database's
// writes lasts (HoldWrites), or a write keeps failing, or across a stop
// (package spill): hours, for a long schema update or compaction.  The rows
// keep the time they happened.  The dashboard's time-cursor rollups fold an
// hour once and move on, so an hour folded before its rows were written
// stayed short of them for good (review finding D9).  Each such writer says
// what it keeps (KeepsUnwritten), and a rollup stops short of the hour of
// the oldest row its source has not written yet (OldestUnwritten).
//
// By source, so that one writer in trouble -- a flush that fails minute
// after minute -- holds back only the rollups of its own rows, and not one
// whose read would then scan the other source raw for as long as it lasts.

// The sources of rows kept unwritten.
const (
	// UnwrittenEvents: unmask_event, the event flusher's.
	UnwrittenEvents = "events"
	// UnwrittenAccessLog: the access-log reader's counts (unmask_traffic_hll,
	// unmask_cookie_minute, unmask_traffic_country_hourly).
	UnwrittenAccessLog = "access_log"
)

// unwrittenKeeper is one writer KeepsUnwritten registered.
type unwrittenKeeper struct {
	source string
	oldest func() (time.Time, bool)
}

// KeepsUnwritten registers a writer that keeps rows of source in memory
// before it writes them to this database.  oldest reports the time of the
// oldest row it keeps and has not written, ok false when it keeps none.  It
// is called from other goroutines, must be quick, and must not touch the
// database.
func (d *DB) KeepsUnwritten(source string, oldest func() (time.Time, bool)) {
	if d == nil || oldest == nil {
		return
	}
	d.unwrittenMu.Lock()
	d.unwritten = append(d.unwritten, unwrittenKeeper{source, oldest})
	d.unwrittenMu.Unlock()
}

// OldestUnwritten is the time of the oldest row of source a registered
// writer keeps and has not written yet; ok is false when none keeps any.
func (d *DB) OldestUnwritten(source string) (oldest time.Time, ok bool) {
	if d == nil {
		return time.Time{}, false
	}
	d.unwrittenMu.Lock()
	keepers := d.unwritten
	d.unwrittenMu.Unlock()
	for _, k := range keepers {
		if k.source != source {
			continue
		}
		if t, kept := k.oldest(); kept && (!ok || t.Before(oldest)) {
			oldest, ok = t, true
		}
	}
	return oldest, ok
}
