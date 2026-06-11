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
//
// Hot reload: batchSize / flushInterval can be updated atomically (= the web
// UI's settings save swaps them in and the next cycle picks them up).
package events

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

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
	f.wg.Add(1)
	go f.run()
	return f
}

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

// SetConfig: hot-reload batchSize / flushInterval (= called from settings save).
func (f *Flusher) SetConfig(batchSize int, intervalMs int) {
	if f == nil {
		return
	}
	if batchSize >= 1 {
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

	flush := func() {
		if len(buf) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := insertBulk(ctx, f.d, buf); err != nil {
			// Retain the batch and retry on the next tick (mirrors
			// nginxlog.flushOnce) instead of dropping it, so a transient DB
			// error — SQLite busy past the timeout, a brief MariaDB blip —
			// doesn't permanently lose the batch.  Bound the retained buffer
			// so a persistent outage can't grow it without limit: overflow
			// drops the OLDEST events and counts them separately from the
			// queue-full drop metric.
			const maxRetain = 5000
			if over := len(buf) - maxRetain; over > 0 {
				f.droppedOnError.Add(uint64(over))
				buf = append(buf[:0], buf[over:]...) // keep newest maxRetain, compact
			}
			log.Printf("events batch flush (n=%d): %v -- retained for retry", len(buf), err)
			lastFlush = time.Now() // back off one interval before retrying
			return
		}
		buf = buf[:0]
		lastFlush = time.Now()
	}

	for {
		select {
		case e := <-f.ch:
			buf = append(buf, e)
			if len(buf) >= int(f.batchSize.Load()) {
				flush()
			}
		case <-t.C:
			interval := time.Duration(f.flushInterval.Load())
			if time.Since(lastFlush) >= interval {
				flush()
			}
		case <-f.done:
			// drain remaining and final flush
			for {
				select {
				case e := <-f.ch:
					buf = append(buf, e)
				default:
					flush()
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
