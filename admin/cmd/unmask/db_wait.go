package main

import (
	"context"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The wait for a database the start could not open.
//
// A daemon on an install that is set up, started while its database was
// away (handlers/db_wait.go has the whole story), keeps serving the
// challenge pages and looks for the database again: after two seconds, then
// at twice the wait each time up to thirty.  When the database answers, the
// daemon starts over in place (reexec.Self) -- the log receiver, the ban
// manager, the event writer and the rollups were never started, and the
// request path reads its handle without a lock, so nothing short of a fresh
// start binds them all.  Through 0.1.55 the open was tried once: a host that
// booted unmask ahead of MariaDB stayed without statistics, bans and an admin
// UI until somebody restarted the service, while systemd saw a live process
// and /healthz said ok.

const (
	// dbWaitFirst is the wait before the first retry; it doubles from there.
	dbWaitFirst = 2 * time.Second
	// dbWaitMax caps the wait between retries.
	dbWaitMax = 30 * time.Second
	// dbWaitSay is how often a wait that goes on says so: the start logged
	// the first failure, the success is logged, and in between one line a
	// minute names the error without filling the journal.
	dbWaitSay = time.Minute
)

// dbWait is the retry loop's world, each part of it replaceable: a test
// drives the loop with a database that answers on the n-th try, a clock of
// its own and no sleep at all.
type dbWait struct {
	// open tries the database once and lets go of it again: nil when it
	// answered.  It gives up when ctx ends.
	open func(ctx context.Context) error
	// restart starts the daemon over in place.  It returns only when that
	// failed (a real one never comes back).
	restart func() error
	// sleep waits d; false when ctx ended first.
	sleep func(ctx context.Context, d time.Duration) bool
	now   func() time.Time
	logf  func(format string, args ...any)
}

// run retries until the database answers and the restart is under way, or
// ctx ends (the shutdown).  A restart that fails is retried with the next
// round: the usual cause, a binary replaced by a package upgrade, is over
// when the package has restarted the service itself.
func (w dbWait) run(ctx context.Context) {
	start := w.now()
	lastSaid := start // the start itself logged the first failure
	restartFailed := false
	wait := dbWaitFirst
	for try := 1; ; try++ {
		if !w.sleep(ctx, wait) {
			return
		}
		err := w.open(ctx)
		if ctx.Err() != nil {
			// The shutdown came while the database was being tried: it
			// wins, whatever the try found.  A restart now would leave the
			// service manager waiting for a process it asked to stop.
			return
		}
		switch now := w.now(); {
		case err == nil:
			if !restartFailed {
				w.logf("db: the database answers again (%s after the start, try %d); starting over in place to run with it",
					now.Sub(start).Round(time.Second), try)
			}
			rerr := w.restart()
			if rerr == nil {
				return
			}
			// Said at once the first time, then once a minute like the rest.
			if !restartFailed || now.Sub(lastSaid) >= dbWaitSay {
				restartFailed, lastSaid = true, now
				w.logf("db: could not start over in place (%v); trying again, or restart the service", rerr)
			}
		case now.Sub(lastSaid) >= dbWaitSay:
			lastSaid = now
			w.logf("db: still unreachable %s after the start (try %d): %v",
				now.Sub(start).Round(time.Second), try, err)
		}
		wait = min(wait*2, dbWaitMax)
	}
}

// probeDB opens the configured database and closes it again: what one try of
// the wait does.  db.Open cannot be told to stop -- a MariaDB that drops the
// packets holds it for the dial and the ping timeouts -- so it runs beside
// the wait for ctx, and a shutdown is not kept waiting for it; the open left
// behind closes its own handle when it returns.
func probeDB(ctx context.Context, cfg settings.DB) error {
	done := make(chan error, 1)
	go func() {
		c, err := db.Open(cfg)
		if err == nil {
			err = c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
