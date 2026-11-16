package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/spill"
)

// Review finding D9.  The rate-limit funnel's rollup folds an hour once and
// moves its cursor past it, and it takes an hour two back as settled.  The
// events of a hold of the database's writes (a schema update or a compaction
// run from the shell) wait in the flusher's memory -- or, across a stop, in
// its spill file -- and keep the time they happened.  After a hold longer
// than the settle horizon their hours are due when the hold ends, and the
// rollups and the flusher each run on a tick of their own: a pass that came
// first folded the hours without the events, the events were written into
// hours the cursor had passed, and the read side takes a folded hour from the
// rollup alone.  The funnel's rate_limit row stayed short of them for good.
//
// Each test holds the events of an hour three back, runs a pass before they
// are written, and then asks for the hour once they are.

// rlHeldEvents: a rate-limited visitor's two serves and a load, ten minutes
// into hour (a UTC unix-hour).
func rlHeldEvents(hour int64) []*events.Event {
	at := time.Unix(hour*3600+600, 0).UTC()
	ip := []byte{198, 51, 100, 7}
	return []*events.Event{
		{Site: "held.example", IPPacked: ip, Phase: "serve", Payload: map[string]any{"rl": 1}, OccurredAt: at},
		{Site: "held.example", IPPacked: ip, Phase: "serve", Payload: map[string]any{"rl": 1}, OccurredAt: at.Add(time.Second)},
		{Site: "held.example", IPPacked: ip, Phase: "load", JA4Verdict: "bot_held", OccurredAt: at.Add(2 * time.Second)},
	}
}

// startHeldFlusher starts the process's event flusher on d, stopped again when
// the test ends.  A flusher an earlier test left running would take the events
// meant for this one.
func startHeldFlusher(t *testing.T, d *db.DB) {
	t.Helper()
	events.StopFlusher()
	t.Cleanup(events.StopFlusher)
	events.StartFlusher(d, 10, 50)
}

// setRollupCursor records name's cursor at hour: where it stood before the hold.
func setRollupCursor(t *testing.T, d *db.DB, name string, hour int64) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO unmask_aggregate_state (name, last_id, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, name, hour); err != nil {
		t.Fatal(err)
	}
}

// checkRateLimitHourFolded waits for the flusher to write the n events it
// kept, runs one rollup pass, and checks that the held hour counts them: in
// the rollup's row for the hour and in the funnel's rate_limit row.
func checkRateLimitHourFolded(t *testing.T, d *db.DB, hour int64, n int) {
	t.Helper()
	ctx := context.Background()
	written := func() int {
		var c int
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	// Written first, then kept by none: the flusher stops saying it keeps
	// them a moment after the commit, and a pass in that moment still waits.
	for deadline := time.Now().Add(30 * time.Second); written() != n || events.HeldEvents() != 0; {
		if time.Now().After(deadline) {
			t.Fatalf("the flusher did not write the events it kept: %d of %d written, %d still kept", written(), n, events.HeldEvents())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := RollupRateLimitFunnel(ctx, d); err != nil {
		t.Fatal(err)
	}

	got := map[string]int64{}
	bucket := time.Unix(hour*3600, 0).UTC().Format("2006-01-02 15")
	rows, err := d.Query(`SELECT bucket_key, cnt FROM unmask_aggregate_hourly WHERE bucket_kind = ? AND bucket_hour = ?`, hkRateLimitFunnel, bucket)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		var c int64
		if err := rows.Scan(&k, &c); err != nil {
			t.Fatal(err)
		}
		got[k] = c
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	cursor, err := stateCursor(ctx, d, rlfState)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct {
		key  string
		want int64
	}{{"p:serve", 2}, {"p:load", 1}, {"s:bot_held", 1}} {
		if got[w.key] != w.want {
			t.Errorf("the rollup's %s for the held hour %s = %d, want %d (cursor at %d, the held hour is %d)", w.key, bucket, got[w.key], w.want, cursor, hour)
		}
	}

	row, ok, err := rateLimitFunnelRowAgg(ctx, d, 24, []string{"bot_held"})
	if err != nil || !ok {
		t.Fatalf("the funnel's rate_limit row: ok=%v err=%v", ok, err)
	}
	if row.Serve != 2 || row.Load != 1 || row.Stealth != 1 {
		t.Errorf("the funnel's rate_limit row: serve %d, load %d, stealth %d; want 2, 1, 1", row.Serve, row.Load, row.Stealth)
	}
}

// The hold ends while the daemon runs: its pass comes before the flusher has
// written what it kept.  Here the pass runs while the writes are still held,
// which makes that order certain.
func TestRateLimitFunnelRollupWaitsForEventsHeldThroughAHold(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	hour := time.Now().Unix()/3600 - 3
	setRollupCursor(t, d, rlfState, hour-1)
	startHeldFlusher(t, d)

	d.HoldWrites(true)
	evs := rlHeldEvents(hour)
	for _, e := range evs {
		events.InsertAsync(d, e)
	}
	for deadline := time.Now().Add(30 * time.Second); events.HeldEvents() != int64(len(evs)); {
		if time.Now().After(deadline) {
			t.Fatalf("the flusher keeps %d events, want the %d of the hold", events.HeldEvents(), len(evs))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := RollupRateLimitFunnel(ctx, d); err != nil {
		t.Fatal(err)
	}
	d.HoldWrites(false)
	checkRateLimitHourFolded(t, d, hour, len(evs))
}

// The daemon was stopped during the hold, and the events it kept went to the
// spill file; the next start takes them back.  Its first pass runs at once,
// before the flusher has written them -- here the writes are still held when
// the daemon starts, which makes that order certain.
func TestRateLimitFunnelRollupWaitsForEventsCarriedAcrossAStop(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	hour := time.Now().Unix()/3600 - 3
	setRollupCursor(t, d, rlfState, hour-1)

	dir := t.TempDir()
	evs := rlHeldEvents(hour)
	if err := spill.Save(dir, events.HeldSpillFile, evs); err != nil {
		t.Fatal(err)
	}
	events.SetSpillDir(dir)
	t.Cleanup(func() { events.SetSpillDir("") })

	d.HoldWrites(true)
	startHeldFlusher(t, d)
	if err := RollupRateLimitFunnel(ctx, d); err != nil {
		t.Fatal(err)
	}
	d.HoldWrites(false)
	checkRateLimitHourFolded(t, d, hour, len(evs))
}
