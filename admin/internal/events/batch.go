// Package events batch flusher: queue + worker that bulk-INSERTs in a single tx.
//
// Flow:
//   - Submit(*Event) enqueues onto the channel (= non-blocking)
//   - The worker goroutine:
//     1) buffer accumulates up to batchSize items    → flush immediately
//     2) flushInterval elapses (= max idle latency)  → flush the rest (= skip when 0)
//     3) Stop() (= shutdown signal) → drain + final flush + exit
//   - Flush inserts every row inside a single transaction (= 10-50x faster on SQLite WAL)
//   - On a full queue, drop + warn log (= prevent OOM from a bot flood)
//   - While a schema update or a compaction holds the database's write lock
//     (db.WritesHeld) nothing is written: the events are kept, up to
//     heldMax, and written when the lock is released
//
// Hot reload: batchSize / flushInterval can be updated atomically (= the web
// UI's settings save swaps them in and the next cycle picks them up).
package events

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/safe"
)

// flusherQueueSize: channel buffer.  Default 10,000 (= absorbs roughly 10 seconds of burst).
// Hardcoded is fine (= excessive bursts drop with a warn log).
const flusherQueueSize = 10000

type Flusher struct {
	d *db.DB

	// Hot-reloadable settings.  Accessed via atomic.
	batchSize     atomic.Int32
	flushInterval atomic.Int64 // nanoseconds

	ch   chan *Event
	done chan struct{}
	wg   sync.WaitGroup

	// metrics (= dropped etc.  For future dashboard visualization).
	dropped        atomic.Uint64 // queue-full drops (Submit on a full channel)
	droppedOnError atomic.Uint64 // overflow drops after a DB-error retry backlog
	// droppedBadRows: rows the database refused for what they carried
	// (insertRows) -- a value no cut made fit, a constraint -- and that
	// were let go so the rest of their batch could be written.
	droppedBadRows atomic.Uint64
	// kept: the events held in memory while the database's writes are held,
	// as of the last tick -- what the admin UI shows during a long run.
	kept atomic.Int64
}

// NewFlusher: start one flusher and return it.  The worker goroutine starts.
// batchSize <= 0 uses 100; intervalMs <= 0 uses 1000.
func NewFlusher(d *db.DB, batchSize int, intervalMs int) *Flusher {
	if batchSize < 1 {
		batchSize = 100
	}
	if intervalMs < 50 {
		intervalMs = 1000
	}
	f := &Flusher{
		d:    d,
		ch:   make(chan *Event, flusherQueueSize),
		done: make(chan struct{}),
	}
	f.batchSize.Store(int32(batchSize))
	f.flushInterval.Store(int64(time.Duration(intervalMs) * time.Millisecond))
	// The widths the rows are cut to (events.go): read before the first
	// write, so that none is refused for a width the catalog could have
	// told.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	LoadColumnWidths(ctx, d)
	cancel()
	f.wg.Add(1)
	go f.run()
	return f
}

// columnWidthsEvery is how often the running flusher re-reads the column
// widths (LoadColumnWidths): an operator applying migration 0048 while
// the daemon runs is noticed within this.
const columnWidthsEvery = 10 * time.Minute

// Submit: non-blocking enqueue.  On a full queue, drop + warn (= bump the dropped counter).
func (f *Flusher) Submit(e *Event) {
	if f == nil || e == nil {
		return
	}
	select {
	case f.ch <- e:
	default:
		// queue full.  Drop and +1 to metrics.  Log every 1024 events (= avoid log spam).
		n := f.dropped.Add(1)
		if n%1024 == 1 {
			log.Printf("events flusher: queue full (size=%d), dropped %d events so far", flusherQueueSize, n)
		}
	}
}

// heldMax is how many events are kept while the database's writes are held.
// An index build over a large table holds the write lock for minutes, and a
// compaction of a large database for longer; the challenge goes on during
// either and its events are worth having afterwards.  Past this many the
// oldest go, counted with the DB-error drops.  At about 1 KB an event, 5% of
// the memory the daemon may use, and never fewer than 50,000
// (db.HeldEventsLimit, which the compaction's plan is checked against).
var heldMax = db.HeldEventsLimit()

// flushChunk bounds one transaction when a backlog is written: the lock is
// released between chunks, so whatever else is waiting to write gets in, and
// no one transaction has to beat the flush's own deadline on a slow disk.
const flushChunk = 500

// backlogPause is the gap between the chunks of a backlog (the events kept
// through a hold): the other writers -- a ban, a notice, the hourly
// aggregate -- take the lock in the gaps, where one chunk after another had
// them waiting out their busy timeout (2026-10-17, a nine-minute backlog).
const backlogPause = 25 * time.Millisecond

// maxRetain bounds what is kept for a retry when writing fails (the database
// is down, full, read-only): a transient failure loses nothing, a persistent
// one cannot grow the buffer without limit.  Events kept through a schema
// update's hold are bounded by heldMax instead -- a failure on the first
// write after the hold must not throw away what the hold kept.
const maxRetain = 5000

// finalFlushWithin bounds the last write at shutdown: long enough to wait
// out a lock that is about to be released, short of the service manager's
// stop timeout.
const finalFlushWithin = 20 * time.Second

// maxBatchSize bounds the hot-reloadable batch size.  Events are flushed in one
// transaction, so a batch this large is already far past useful; the point of
// the ceiling is that the value is narrowed to int32 below.
const maxBatchSize = 1 << 20

// SetConfig: hot-reload batchSize / flushInterval (= called from settings save).
func (f *Flusher) SetConfig(batchSize int, intervalMs int) {
	if f == nil {
		return
	}
	// Clamped before the narrowing conversion: int is 64-bit here and the
	// counter is 32, so a settings value above math.MaxInt32 would wrap -- a
	// large positive batch size arriving as a negative one, which reads as
	// "flush never".  The ceiling is far above any useful batch anyway.
	if batchSize >= 1 {
		if batchSize > maxBatchSize {
			batchSize = maxBatchSize
		}
		f.batchSize.Store(int32(batchSize))
	}
	if intervalMs >= 50 {
		f.flushInterval.Store(int64(time.Duration(intervalMs) * time.Millisecond))
	}
}

// Stop: drain the queue, emit the final flush, then stop the worker.
// Call from a graceful shutdown such as SIGTERM.
func (f *Flusher) Stop() {
	if f == nil {
		return
	}
	close(f.done)
	f.wg.Wait()
}

// DroppedCount: returns the cumulative number of events dropped due to a full queue.
func (f *Flusher) DroppedCount() uint64 {
	if f == nil {
		return 0
	}
	return f.dropped.Load()
}

// DroppedOnErrorCount: cumulative events dropped because a DB-error retry
// backlog exceeded the retained-buffer cap.  Distinct from DroppedCount
// (queue-full) so the two failure modes are attributable separately.
func (f *Flusher) DroppedOnErrorCount() uint64 {
	if f == nil {
		return 0
	}
	return f.droppedOnError.Load()
}

// DroppedBadRowsCount: cumulative rows the database refused for their own
// data and that were let go so the rest of their batch could be written
// (insertRows).  A third failure mode, apart from the two above: the row,
// not the queue or the database, was the problem.
func (f *Flusher) DroppedBadRowsCount() uint64 {
	if f == nil {
		return 0
	}
	return f.droppedBadRows.Load()
}

// GlobalFlusherDroppedBadRows is DroppedBadRowsCount of the process's
// flusher.  Used by metrics / status.
func GlobalFlusherDroppedBadRows() uint64 {
	if f := globalFlusher.Load(); f != nil {
		return f.DroppedBadRowsCount()
	}
	return 0
}

func (f *Flusher) run() {
	defer f.wg.Done()
	defer safe.Recover("events-flusher") // a panic here must not crash the daemon
	buf := make([]*Event, 0, 512)
	// Ideally the ticker would re-read flushInterval each tick, but stdlib's
	// Ticker cannot change interval, so poll on a short interval (= 100ms)
	// and gate the actual flush on elapsed time.
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	lastFlush := time.Now()
	widthsRead := time.Now()
	holding := false
	// kept: buf holds events kept through a hold, not yet all written.
	kept := false
	heldDropped := 0

	// retain trims buf to max events, dropping the oldest and counting them.
	// It drops a tenth more than it has to, so that a flood arriving past
	// the limit is trimmed now and then rather than copied at every event.
	retain := func(max int) int {
		if len(buf) <= max {
			return 0
		}
		over := len(buf) - max + max/10
		if over > len(buf) {
			over = len(buf)
		}
		f.droppedOnError.Add(uint64(over))
		buf = append(buf[:0], buf[over:]...)
		return over
	}
	// drain takes what has queued meanwhile into buf: a long write -- the
	// backlog of a hold, minutes on a slow disk -- must not leave the queue
	// to fill and drop while it goes (2026-10-17: it did, by the thousand).
	drain := func() {
		for {
			select {
			case e := <-f.ch:
				buf = append(buf, e)
			default:
				return
			}
		}
	}
	// write writes buf out a chunk at a time and reports the first failure;
	// what failed stays in buf.  Between the chunks of a backlog the queue is
	// drained and the lock left alone for a moment.
	write := func(within time.Duration) error {
		deadline := time.Now().Add(within)
		for len(buf) > 0 {
			n := min(len(buf), flushChunk)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			consumed := 0
			err := insertBulk(ctx, f.d, buf[:n])
			switch {
			case err == nil:
				consumed = n
			case isDataError(err):
				// The chunk holds a row the database refuses for what it
				// carries.  Written again row by row, so that the row is
				// what is lost and not the chunk -- which, kept and
				// retried whole, would have failed on it every time.
				consumed, err = f.insertRows(ctx, buf[:n], err)
			}
			cancel()
			if consumed > 0 {
				buf = append(buf[:0], buf[consumed:]...)
			}
			if err != nil {
				return err
			}
			drain()
			if kept && len(buf) > 0 {
				time.Sleep(backlogPause)
			}
		}
		return nil
	}

	flush := func(final bool) {
		if len(buf) == 0 {
			return
		}
		if f.d.WritesHeld() && !final {
			// A write now would wait out the busy timeout and fail, over
			// and over for as long as the build runs.  Keep the events.
			heldDropped += retain(heldMax)
			f.kept.Store(int64(len(buf)))
			if !holding {
				holding, kept = true, true
				log.Printf("events flusher: the database's writes are held (a schema update or a compaction); events are kept in memory (up to %d) and written when it has finished", heldMax)
			}
			lastFlush = time.Now()
			return
		}
		if holding {
			holding = false
			if heldDropped > 0 {
				log.Printf("events flusher: the write lock is free again; writing the %d event(s) kept meanwhile (%d older ones over the limit were dropped)", len(buf), heldDropped)
			} else {
				log.Printf("events flusher: the write lock is free again; writing the %d event(s) kept meanwhile", len(buf))
			}
			heldDropped = 0
		}
		within := 10 * time.Second
		if kept {
			within = time.Minute // the backlog of a whole hold
		}
		if final {
			within = finalFlushWithin
		}
		if err := write(within); err != nil {
			if final {
				f.droppedOnError.Add(uint64(len(buf)))
				log.Printf("events flusher: %d event(s) could not be written before shutdown: %v", len(buf), err)
				buf = buf[:0]
				return
			}
			if kept && errors.Is(err, context.DeadlineExceeded) {
				// A backlog outlasts one turn: what was written is written,
				// the rest goes on at the next tick.  Not a failure, and
				// nothing is dropped for it.
				f.kept.Store(int64(len(buf)))
				log.Printf("events flusher: %d event(s) of the backlog still to write", len(buf))
				lastFlush = time.Now()
				return
			}
			// Retain and retry on the next tick (mirrors nginxlog.flushOnce):
			// a transient error -- SQLite busy past the timeout, a brief
			// MariaDB blip -- loses nothing; a persistent one is bounded,
			// dropping the oldest.
			limit := maxRetain
			if kept {
				limit = heldMax
			}
			if n := retain(limit); n > 0 {
				log.Printf("events batch flush: %v -- %d retained for retry, %d oldest dropped", err, len(buf), n)
			} else {
				log.Printf("events batch flush: %v -- %d retained for retry", err, len(buf))
			}
			lastFlush = time.Now() // back off one interval before retrying
			return
		}
		kept = false
		f.kept.Store(0)
		lastFlush = time.Now()
	}

	for {
		select {
		case e := <-f.ch:
			buf = append(buf, e)
			// While holding, the batch size is no reason to try: the tick
			// trims and waits.
			if !holding && len(buf) >= int(f.batchSize.Load()) {
				flush(false)
			}
		case <-t.C:
			interval := time.Duration(f.flushInterval.Load())
			if time.Since(lastFlush) >= interval || (holding && len(buf) > heldMax) {
				flush(false)
			}
			if time.Since(widthsRead) >= columnWidthsEvery {
				widthsRead = time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				LoadColumnWidths(ctx, f.d)
				cancel()
			}
		case <-f.done:
			// Drain what is queued and write it all, the hold or not: this
			// is the last chance, and a run that held the lock has been
			// stopped by now (the daemon's shutdown stops its own).
			for {
				select {
				case e := <-f.ch:
					buf = append(buf, e)
				default:
					flush(true)
					return
				}
			}
		}
	}
}

// insertBulk: INSERT N rows inside a single transaction.  Mid-flight failure rolls back everything.
// Both SQLite WAL and MariaDB transactions commit per batch, so it is a single write.
func insertBulk(ctx context.Context, d *db.DB, events []*Event) error {
	if len(events) == 0 || d == nil {
		return nil
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, insertStmt)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		args := prepareInsertArgs(e)
		if args == nil {
			continue
		}
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// isDataError reports whether a write failed for what a row carries -- a
// value longer than its column, one that is not valid UTF-8, one out of
// range -- rather than for the state of the database (locked, down, full),
// which a retry of the same rows can cure.  MariaDB's own codes, and the
// messages for an error the driver did not type.
func isDataError(err error) bool {
	if err == nil {
		return false
	}
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		switch me.Number {
		case 1406, // data too long for column
			1366, // incorrect string value
			1265, // data truncated for column
			1264: // out of range value for column
			return true
		}
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Data too long") || strings.Contains(msg, "Incorrect string value")
}

// insertRows writes events one row at a time, each its own transaction,
// after insertBulk refused the chunk for a row's data (cause).  A row the
// database refuses for its data is let go and counted (DroppedBadRowsCount);
// a failure of any other kind ends the pass, and the row and those after
// it stay for the retry.  Returns how many rows were consumed -- written or
// let go -- and that other failure, if one ended the pass.
func (f *Flusher) insertRows(ctx context.Context, events []*Event, cause error) (consumed int, err error) {
	bad := 0
	var first error
	defer func() {
		if bad > 0 {
			f.droppedBadRows.Add(uint64(bad))
			log.Printf("events batch flush: the database refused %d row(s) of %d for their data, which were dropped (first: %v); the rest of the batch was written row by row", bad, len(events), first)
		}
	}()
	for _, e := range events {
		args := prepareInsertArgs(e)
		if args == nil {
			consumed++
			continue
		}
		if _, err := f.d.ExecContext(ctx, insertStmt, args...); err != nil {
			if !isDataError(err) {
				return consumed, err
			}
			if first == nil {
				first = err
			}
			bad++
		}
		consumed++
	}
	if bad == 0 {
		// Every row went in on its own: the chunk failed as a whole for a
		// reason the pass did not meet again.  Said, since the cause named
		// a row and none was found.
		log.Printf("events batch flush: the batch was refused (%v) but every row of it was written on its own", cause)
	}
	return consumed, nil
}

// HeldEvents is how many events the flusher keeps in memory while the
// database's writes are held (0 when they are not, or there is no flusher).
func HeldEvents() int64 {
	if f := globalFlusher.Load(); f != nil {
		return f.kept.Load()
	}
	return 0
}
