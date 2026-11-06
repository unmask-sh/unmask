package events

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// writtenOf reads one series of the process's counter.
func writtenOf(phase, verdict string) uint64 {
	for _, c := range WrittenCounts() {
		if c.Phase == phase && c.Verdict == verdict {
			return c.N
		}
	}
	return 0
}

func writtenTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "w.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// The counter behind unmask_event_total moves when the database has taken a
// row, on each of the three paths that write one, and by exactly the rows
// written: a batch that the flusher commits, the row-by-row pass after a
// refused batch, and the direct insert.  The verdicts are this test's own,
// so the figures are exact whatever else the package has written.
func TestWrittenCountsFollowTheWrites(t *testing.T) {
	d := writtenTestDB(t)
	rows := func(phase, verdict string) uint64 {
		t.Helper()
		var n uint64
		q := `SELECT COUNT(*) FROM unmask_event WHERE phase = ? AND ja4_verdict = ?`
		if err := d.QueryRow(q, phase, verdict).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ev := func(phase, verdict string) *Event {
		return &Event{Site: "s", IPPacked: PackIP("192.0.2.7"), Phase: phase, JA4Verdict: verdict}
	}
	noneBefore := writtenOf("serve", WrittenVerdictNone)

	// The flusher: one committed batch, counted when it has been written.
	f := NewFlusher(d, 100, 50)
	for i := 0; i < 3; i++ {
		f.Submit(ev("serve", "written_flush"))
	}
	f.Submit(ev("load", "written_flush"))
	f.Submit(ev("load", "written_flush"))
	f.Submit(ev("serve", ""))                    // no verdict: "(none)"
	f.Submit(ev("not_a_phase", "written_flush")) // never written, never counted
	if got := writtenOf("serve", "written_flush"); got != 0 && rows("serve", "written_flush") == 0 {
		t.Errorf("%d row(s) counted before any was written", got)
	}
	f.Stop() // the final flush
	for _, c := range []struct {
		phase string
		want  uint64
	}{{"serve", 3}, {"load", 2}} {
		if got, inDB := writtenOf(c.phase, "written_flush"), rows(c.phase, "written_flush"); got != c.want || inDB != c.want {
			t.Errorf("after the flush, %s: counted %d, %d in the table, want %d", c.phase, got, inDB, c.want)
		}
	}
	if got := writtenOf("serve", WrittenVerdictNone) - noneBefore; got != 1 {
		t.Errorf("a row with no verdict: %d counted under %q, want 1", got, WrittenVerdictNone)
	}
	if got := writtenOf("not_a_phase", "written_flush"); got != 0 {
		t.Errorf("%d row(s) counted for a phase that is never written", got)
	}

	// Row by row, as after a batch the database refused for one row's data.
	consumed, err := f.insertRows(context.Background(),
		[]*Event{ev("serve", "written_rows"), ev("captcha", "written_rows"), ev("not_a_phase", "written_rows")},
		errors.New("a refused batch"))
	if err != nil || consumed != 3 {
		t.Fatalf("insertRows: consumed %d, %v", consumed, err)
	}
	if s, c := writtenOf("serve", "written_rows"), writtenOf("captcha", "written_rows"); s != 1 || c != 1 {
		t.Errorf("row by row: serve %d, captcha %d, want 1 and 1", s, c)
	}

	// The direct insert (the beacon's path).
	if err := Insert(context.Background(), d, ev("verify_ng", "written_direct")); err != nil {
		t.Fatal(err)
	}
	if got := writtenOf("verify_ng", "written_direct"); got != 1 {
		t.Errorf("direct insert: counted %d, want 1", got)
	}

	// A write the database did not take is not counted: closed, it takes none.
	_ = d.Close()
	if err := Insert(context.Background(), d, ev("serve", "written_failed")); err == nil {
		t.Fatal("an insert into a closed database succeeded")
	}
	if err := insertBulk(context.Background(), d, []*Event{ev("serve", "written_failed")}); err == nil {
		t.Fatal("a batch into a closed database succeeded")
	}
	if got := writtenOf("serve", "written_failed"); got != 0 {
		t.Errorf("%d row(s) counted that the database never took", got)
	}
}

// A verdict is a header's value, and a series lives as long as the process:
// past writtenMaxSeries distinct pairs, further verdicts are counted under
// their phase's "(other)" -- every row still counted, the set of series
// bounded -- while the series already known go on counting as themselves.
func TestWrittenSeriesAreBounded(t *testing.T) {
	w := &writtenCounter{n: map[writtenKey]uint64{}}
	const extra = 250
	for i := 0; i < writtenMaxSeries+extra; i++ {
		w.add(writtenKey{"serve", fmt.Sprintf("v%04d", i)}, 1)
	}
	w.add(writtenKey{"load", "late"}, 3)   // a phase first seen past the limit
	w.add(writtenKey{"serve", "v0000"}, 5) // a series from before it

	var total, own, other uint64
	byKey := map[writtenKey]uint64{}
	for k, n := range w.n {
		byKey[k] = n
		total += n
		if k.verdict == WrittenVerdictOther {
			other += n
		} else {
			own++
		}
	}
	if own != writtenMaxSeries {
		t.Errorf("%d series with a verdict of their own, want the limit %d", own, writtenMaxSeries)
	}
	if len(byKey) != writtenMaxSeries+2 {
		t.Errorf("%d series in all, want %d and one overflow for each of the two phases", len(byKey), writtenMaxSeries)
	}
	if want := uint64(writtenMaxSeries + extra + 3 + 5); total != want {
		t.Errorf("%d rows counted, want every one of %d", total, want)
	}
	if got := byKey[writtenKey{"serve", WrittenVerdictOther}]; got != extra {
		t.Errorf("serve overflow %d, want %d", got, extra)
	}
	if got := byKey[writtenKey{"load", WrittenVerdictOther}]; got != 3 {
		t.Errorf("load overflow %d, want 3", got)
	}
	if got := byKey[writtenKey{"serve", "v0000"}]; got != 6 {
		t.Errorf("a series known before the limit counted %d, want 6", got)
	}
	if other != extra+3 {
		t.Errorf("overflow holds %d rows, want %d", other, extra+3)
	}

	// A batch goes through the same bound.
	w.addAll(map[writtenKey]uint64{{"serve", "another"}: 2, {"serve", "v0001"}: 4})
	if got := w.n[writtenKey{"serve", WrittenVerdictOther}]; got != extra+2 {
		t.Errorf("serve overflow after a batch %d, want %d", got, extra+2)
	}
	if got := w.n[writtenKey{"serve", "v0001"}]; got != 5 {
		t.Errorf("a known series in a batch counted %d, want 5", got)
	}
}

// The series a row is counted under is its phase and its verdict as stored:
// cut to the column, and "(none)" where the table has NULL.
func TestWrittenKeyIsTheStoredVerdict(t *testing.T) {
	long := ""
	for i := 0; i < widthVerdict+20; i++ {
		long += "v"
	}
	if k := writtenKeyOf(&Event{Phase: "serve", JA4Verdict: long}); len(k.verdict) != widthVerdict || k.phase != "serve" {
		t.Errorf("a verdict past the column: %d characters under phase %q", len(k.verdict), k.phase)
	}
	if k := writtenKeyOf(&Event{Phase: "load"}); k.verdict != WrittenVerdictNone {
		t.Errorf("no verdict is counted under %q, want %q", k.verdict, WrittenVerdictNone)
	}
	// WrittenCounts is ordered, so a scrape reads the same lines in the same
	// order every time.
	prev := WrittenCount{}
	for i, c := range WrittenCounts() {
		if i > 0 && (c.Phase < prev.Phase || (c.Phase == prev.Phase && c.Verdict <= prev.Verdict)) {
			t.Fatalf("WrittenCounts out of order at %d: %+v after %+v", i, c, prev)
		}
		prev = c
	}
}
