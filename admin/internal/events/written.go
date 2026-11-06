package events

import (
	"sort"
	"sync"
)

// The rows this process has written to unmask_event, by phase and verdict:
// what /metrics exports as unmask_event_total.
//
// That metric was declared a counter and read from the table -- the rows of
// the last 24 hours, grouped -- so its value went down whenever a row left
// the window, and a rate() or increase() over it read every such step as a
// counter reset and added the whole value back on.  A counter has to be
// counted where the thing happens: here, each time the database has taken a
// row, on every path that writes one (insertBulk, Flusher.insertRows,
// insertDirect).  It starts at zero with the process and only goes up, and a
// scrape reads memory, not the table.

// WrittenCount is one series: the rows written for a phase and verdict since
// the process started.
type WrittenCount struct {
	Phase   string
	Verdict string
	N       uint64
}

const (
	// WrittenVerdictNone stands for a row with no verdict, as the table's
	// NULL has always been exported.
	WrittenVerdictNone = "(none)"
	// WrittenVerdictOther takes the rows of every verdict past the limit
	// below, per phase.
	WrittenVerdictOther = "(other)"
	// writtenMaxSeries bounds the distinct phase and verdict pairs counted
	// one by one.  The phases are a fixed list and the verdicts come from
	// the settings' rules, a few dozen at most; the verdict of a row is
	// nonetheless a header's value, and a series is kept until the process
	// ends, so what a client could put there must not be able to grow the
	// set without limit.
	writtenMaxSeries = 500
)

type writtenKey struct{ phase, verdict string }

// writtenKeyOf is the series a written row belongs to: its phase and its
// verdict as stored (cut to the column, see prepareInsertArgs).
func writtenKeyOf(e *Event) writtenKey {
	v := fit(e.JA4Verdict, widthVerdict)
	if v == "" {
		v = WrittenVerdictNone
	}
	return writtenKey{e.Phase, v}
}

type writtenCounter struct {
	mu sync.Mutex
	n  map[writtenKey]uint64
	// own: how many of n's keys carry a verdict of their own (the rest are
	// the per-phase overflow), which is what writtenMaxSeries bounds.
	own int
}

var written = &writtenCounter{n: map[writtenKey]uint64{}}

// add counts n rows of series k.  A series that would be the first past the
// limit is counted under its phase's overflow instead.
func (w *writtenCounter) add(k writtenKey, n uint64) {
	if n == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addLocked(k, n)
}

func (w *writtenCounter) addLocked(k writtenKey, n uint64) {
	if _, known := w.n[k]; !known && k.verdict != WrittenVerdictOther {
		if w.own >= writtenMaxSeries {
			k.verdict = WrittenVerdictOther
		} else {
			w.own++
		}
	}
	w.n[k] += n
}

// addAll counts a batch under one lock.
func (w *writtenCounter) addAll(batch map[writtenKey]uint64) {
	if len(batch) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, n := range batch {
		w.addLocked(k, n)
	}
}

// WrittenCounts returns the rows written since the process started, one
// entry per phase and verdict, ordered by phase then verdict.
func WrittenCounts() []WrittenCount {
	written.mu.Lock()
	out := make([]WrittenCount, 0, len(written.n))
	for k, n := range written.n {
		out = append(out, WrittenCount{Phase: k.phase, Verdict: k.verdict, N: n})
	}
	written.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Phase != out[j].Phase {
			return out[i].Phase < out[j].Phase
		}
		return out[i].Verdict < out[j].Verdict
	})
	return out
}
