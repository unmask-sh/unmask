package main

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/handlers"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/safe"
)

// The daemon's background loops: the periodic work cmdServe starts beside
// the HTTP server.  Each runs under the group's context and stops between
// its steps when the context ends, and the shutdown waits for them before
// the handles they use (the database, the log receiver, the ban manager)
// are closed.  Until 0.1.54 they were started with no context and no group:
// the shutdown closed the database and the loops went on against it until
// the process ended.

// workerGroup is the set of background loops, under one context.
type workerGroup struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newWorkerGroup(parent context.Context) *workerGroup {
	ctx, cancel := context.WithCancel(parent)
	return &workerGroup{ctx: ctx, cancel: cancel}
}

// Context is the group's: ended by Cancel.
func (g *workerGroup) Context() context.Context { return g.ctx }

// Go starts fn as a worker: a goroutine under the group's context, waited
// for by Wait, with a panic in it logged rather than fatal (safe.Recover;
// the loops recover each step on their own so one failure does not end
// them -- this is the last resort).
func (g *workerGroup) Go(name string, fn func(ctx context.Context)) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer safe.Recover(name)
		fn(g.ctx)
	}()
}

// Cancel ends the group's context: every worker stops at its next step.
func (g *workerGroup) Cancel() { g.cancel() }

// Wait waits for every worker to return, up to limit; false when one is
// still running at the limit.
func (g *workerGroup) Wait(limit time.Duration) bool {
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(limit):
		return false
	}
}

// sleepCtx waits d, or until ctx ends; false then.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// tick waits for the ticker's next tick, or until ctx ends; false then.
func tick(ctx context.Context, t *time.Ticker) bool {
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// runLimiterPurge drops the rate limiter's stale entries (no hits in the
// last hour) every minute, so the table does not grow with every address
// ever seen.
func runLimiterPurge(ctx context.Context, limiter *ratelimit.Limiter) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for tick(ctx, t) {
		safe.Run("limiter-purge", limiter.Purge)
	}
}

// runIPGeoAutoUpdate keeps a managed mmdb current.  Checked DAILY against
// the snapshot's own build date rather than run monthly on a fixed day:
// DB-IP publishes several days into the month, and a monthly timer that
// fires before the new snapshot exists simply skips that month -- which is
// how the mirror came to serve a three-week-old file.  A daily check that
// only downloads something newer self-corrects and costs one conditional
// request.
//
// Same gating as AutoFetch (managed paths, setup complete) at the caller:
// the operator's own mmdb_path is never touched, and an install with no
// mmdb is AutoFetch's business, not this loop's.
func runIPGeoAutoUpdate(ctx context.Context, h *handlers.Handler, gip *ipgeo.Reader, renderNow func(nginxconf.RenderCause) error, renderOutDir func() string) {
	const (
		checkEvery = 24 * time.Hour
		staleAfter = 30 * 24 * time.Hour
	)
	// Settle first: startup already has the first-run fetch, migrations
	// and the nginx render competing for the same minutes, and a month
	// -old file is not urgent.
	if !sleepCtx(ctx, 10*time.Minute) {
		return
	}
	for {
		// One pass under its own recovery (safe.Run): a panic in
		// a pass is logged and the next pass runs, where one in
		// the loop would have ended the checks for good.
		safe.Run("ipgeo-auto-update", func() {
			// Re-read settings each pass so a toggle in the web UI takes
			// effect without a restart (same pattern as the other loops).
			cur := h.SnapshotSettings()
			if cur.IPGeo.AutoUpdate || cur.IPGeo.AutoUpdateASN {
				if ipgeo.AutoUpdateStaleKinds(cur.IPGeo.MMDBPath, cur.IPGeo.MMDBASNPath,
					cur.IPGeo.AutoUpdate, cur.IPGeo.AutoUpdateASN, gip, staleAfter, time.Time{}) > 0 {
					renderAfterGeoUpdate(func() error { return renderNow(nginxconf.RenderCause{Kind: nginxconf.RenderByGeoIP}) }, renderOutDir())
				}
			}
		})
		if !sleepCtx(ctx, checkEvery) {
			return
		}
	}
}

// runRetentionPrune prunes old rows from unmask_event every hour (those
// exceeding EventsRetentionDays), and the audit log, the notification list
// and the ask history on their own retentions.  Aggregates
// (unmask_aggregate) are kept permanently.  retention <= 0 -> no-op.  Run
// once at startup to sweep backlog from immediately after install /
// restart.  Snapshotting settings per run hot-picks up web UI saves.
//
// Hourly, not daily: a run that stops on its budget (or on a busy lock)
// used to leave the remainder for the next day, and on a busy install a
// day's intake outran what one run deleted -- the file grew for weeks
// (2026-09-08: 36 GB against a 7-day window).  Small hourly runs keep
// the backlog near zero, and the prune paces itself against the other
// writers (see events.PruneOldEventsOpts).
func runRetentionPrune(ctx context.Context, h *handlers.Handler, conn *db.DB) {
	runPrune := func() {
		defer safe.Recover("retention-prune") // a panic here must not kill the daemon
		// 45 minutes of the hour: the prune holds the write lock for
		// a second at most at a time and yields at least as long in
		// between, so a long budget is not a long lock -- it is how
		// fast a backlog drains (a week of intake in a day or so).
		// Under the worker's context, so a shutdown ends the run at its
		// next chunk.
		rctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
		defer cancel()
		// One consistent snapshot for this run (settingsPtr is unexported;
		// SnapshotSettings hot-picks up web UI saves on the next tick).
		cfg := h.SnapshotSettings()
		// Admin-action audit log first: it is tiny and must not lose its
		// daily run to an events prune that used the whole budget.
		// (Independent retention; checked separately so
		// events_retention_days=0 doesn't disable it.  Its own
		// default is 0: the log is kept until the operator sets a
		// number.)
		if h.UserRepo != nil {
			if retention := cfg.AuditLogRetentionDays; retention > 0 {
				if n, err := h.UserRepo.PruneOldAudit(rctx, retention); err != nil {
					log.Printf("audit prune: %v", err)
				} else if n > 0 {
					log.Printf("audit prune: deleted %d row(s) older than %d days", n, retention)
				}
			}
		}
		// The notification list, on its own retention (also kept by
		// default).
		if h.Notices != nil {
			if retention := cfg.NoticeRetentionDays; retention > 0 {
				if n, err := h.Notices.Prune(rctx, retention); err != nil {
					log.Printf("notice prune: %v", err)
				} else if n > 0 {
					log.Printf("notice prune: deleted %d row(s) older than %d days", n, retention)
				}
			}
		}
		// The ask page's history, on its own retention (kept by default:
		// a turn is a few KB, and the record is the operator's own).
		if retention := cfg.AskHistoryRetentionDays; retention > 0 {
			if n, err := h.PruneAskHistory(rctx, retention); err != nil {
				log.Printf("ask history prune: %v", err)
			} else if n > 0 {
				log.Printf("ask history prune: deleted %d row(s) older than %d days", n, retention)
			}
		}
		// Raw traffic events.  (The per-hour, per-crawler drill-down that
		// backs the AI-card trend sparkline is NOT pruned here anymore --
		// it moved to PruneHourly's fixed 32-day aggregate window so that
		// lowering events_retention_days for disk does not shorten the
		// crawler trend.  events_retention_days now governs only raw events:
		// the bot-hunt log, --ref lookups, rankings and analyze.)
		if retention := cfg.EventsRetentionDays; retention > 0 {
			// The run's record (unmask_maint_state) is what doctor and the
			// retention tab judge "keeping up" by; write it before and after
			// so a run cut short still shows when it started.
			rec := db.PruneRecord{StartedAt: time.Now().Unix(), Retention: retention}
			var prev db.PruneRecord
			if ok, _ := conn.LoadMaintState(rctx, db.MaintEventsPrune, &prev); ok {
				rec.CompletedAt = prev.CompletedAt
			}
			_ = conn.SaveMaintState(rctx, db.MaintEventsPrune, rec)
			res, err := events.PruneOldEventsOpts(rctx, conn, retention, events.PruneOptions{})
			rec.EndedAt = time.Now().Unix()
			rec.Deleted, rec.Chunks, rec.BusyRetries, rec.Seconds = res.Deleted, res.Chunks, res.BusyRetries, res.Elapsed.Seconds()
			switch {
			case err != nil && errors.Is(err, context.DeadlineExceeded):
				// Committed chunks survive; say how far it got so a budget
				// stop on a big backlog reads as progress, not as a prune
				// that does nothing.
				rec.Err = "budget reached"
				log.Printf("events prune: budget reached after %d row(s) in %d chunk(s) (%d busy retries); the next hourly run continues", res.Deleted, res.Chunks, res.BusyRetries)
			case err != nil && errors.Is(err, context.Canceled):
				// The shutdown: what was deleted stays deleted, and the
				// next start's run continues.
				rec.Err = "stopped"
				log.Printf("events prune: stopped after %d row(s) in %d chunk(s); the next run continues", res.Deleted, res.Chunks)
			case err != nil:
				rec.Err = err.Error()
				log.Printf("events prune: %v (deleted %d row(s) first; the next hourly run continues)", err, res.Deleted)
			default:
				rec.CompletedAt = rec.EndedAt
				if res.Deleted > 0 {
					log.Printf("events prune: deleted %d row(s) older than %d days in %d chunk(s), %v (%d busy retries)", res.Deleted, retention, res.Chunks, res.Elapsed.Round(time.Second), res.BusyRetries)
				}
			}
			// The record is written outside the run's budget (and outside
			// the shutdown's cancellation): a deadline must not also lose
			// the note that says the deadline hit.
			wctx, wcancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := conn.SaveMaintState(wctx, db.MaintEventsPrune, rec); err != nil {
				log.Printf("events prune: record state: %v", err)
			}
			wcancel()
		}
	}
	runPrune()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for tick(ctx, t) {
		// Not against a schema update's write lock: the next hour's
		// run takes what this one leaves.
		if conn.WritesHeld() {
			continue
		}
		runPrune()
	}
}

// runWALWatch minds the write-ahead log.  journal_size_limit truncates it
// to 64 MB after a checkpoint, but a checkpoint can only finish when no
// reader holds an older snapshot: on a large database with long dashboard
// queries the readers overlap and the file grows for as long as they do
// (10.7 GB on 2026-09-08), and the stop that follows has a checkpoint to do
// that no init system waits for.  Every five minutes, when the log is past
// db.WALLargeBytes, trim it as far as the readers allow (db.TrimWAL) and
// say what happened -- once an hour while it stays large, so the log names
// the condition without repeating it.  SQLite only (the caller's choice).
func runWALWatch(ctx context.Context, conn *db.DB) {
	var lastSaid time.Time
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	// One tick under its own recovery (safe.Run): a panic in a
	// tick is logged and the watch goes on, where one in the loop
	// would have ended it for good.
	for tick(ctx, t) {
		safe.Run("wal-watch", func() {
			sz := conn.WALSize()
			if sz < db.WALLargeBytes {
				return
			}
			// A schema update writes its index into the log and holds
			// the lock until it is done: large, not shrinking, and as
			// intended.  It checkpoints the log itself when it ends.
			if conn.WritesHeld() {
				return
			}
			tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			tr, err := conn.TrimWAL(tctx)
			cancel()
			if err != nil {
				log.Printf("wal: %s, trim: %v", humanBytesCLI(sz), err)
				return
			}
			if tr.After < db.WALLargeBytes {
				log.Printf("wal: trimmed from %s to %s", humanBytesCLI(tr.Before), humanBytesCLI(tr.After))
				lastSaid = time.Time{}
				return
			}
			if time.Since(lastSaid) < time.Hour {
				return
			}
			lastSaid = time.Now()
			held := "a reader holds an older snapshot"
			if tr.Blocked {
				held = "a reader is still on the log"
			}
			log.Printf("wal: %s and not shrinking (checkpoint copied %d of %d frames; %s) -- long-running queries keep it; a stop that is killed leaves it for the next start to replay", humanBytesCLI(tr.After), tr.Passive.Checkpointed, tr.Passive.LogFrames, held)
		})
	}
}

// runHourlyAggregate rolls new unmask_event rows into
// unmask_aggregate_hourly every 60s (plus a startup pass).  The stats page
// reads those hourly rollups instead of scanning the raw event table, which
// is ~10x slower under pure-Go SQLite.  PruneHourly trims buckets past the
// 32-day window roughly hourly.  Fully in-process: no external cron
// required.
func runHourlyAggregate(ctx context.Context, conn *db.DB, gip *ipgeo.Reader) {
	// Each rollup runs under its own budget.  They used to share one
	// five-minute context: on a host with a long event backlog the
	// hourly fold spent all of it every tick, and the rollups behind
	// it -- the install-wide one DailyPassByDay reads -- got a context
	// that had already expired, so their cursors never moved and the
	// card scanned 30 days of per-minute rows instead (the company
	// host, 2026-09-12).  The fold's own budget is the longest: it
	// stops between chunks and continues next tick (AggregateHourly).
	// Every budget is under the worker's context, so a shutdown ends a
	// rollup at its next chunk and the cursor keeps what was folded.
	stage := func(name string, budget time.Duration, fn func(context.Context) error) {
		sctx, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		if err := fn(sctx); err != nil && ctx.Err() == nil {
			log.Printf("%s: %v", name, err)
		}
	}
	runAgg := func() {
		defer safe.Recover("hourly-aggregate") // panic must not kill the daemon
		stage("hourly aggregate", 3*time.Minute, func(ctx context.Context) error {
			return dashboard.AggregateHourly(ctx, conn, gip)
		})
		// Fold per-minute traffic sketches into hourly rollups so the
		// DailyUniqueIPs card merges ~720 sketches, not ~65k rows.
		stage("traffic-hll rollup", 2*time.Minute, func(ctx context.Context) error {
			return dashboard.RollupTrafficHLL(ctx, conn)
		})
		// Fold the per-minute nginx-log tables into install-wide hourly
		// aggregates so the default (unfiltered) DailyUniqueIPs /
		// DailyPassByDay cards skip the ~300-site read fan-out.
		stage("install-wide rollup", 2*time.Minute, func(ctx context.Context) error {
			return dashboard.RollupInstallWideHourly(ctx, conn)
		})
		// Same idea for the per-country pass chart (DailyPassByCountry):
		// collapse the per-site country_hourly rows into install-wide ones.
		stage("install-wide country rollup", 2*time.Minute, func(ctx context.Context) error {
			return dashboard.RollupInstallWideCountry(ctx, conn)
		})
		// Pre-aggregate the Funnel card's rate_limit row per hour so it
		// stops running a per-IP self-join over unmask_event on each load.
		stage("rate-limit funnel rollup", 2*time.Minute, func(ctx context.Context) error {
			return dashboard.RollupRateLimitFunnel(ctx, conn)
		})
		// Install-wide 'ipc'/'ipp' sketches so the overview's non-human-%
		// card skips the per-site traffic_hll fan-out.
		stage("install-wide blocked rollup", 2*time.Minute, func(ctx context.Context) error {
			return dashboard.RollupInstallWideBlocked(ctx, conn)
		})
	}
	runPrune := func() {
		defer safe.Recover("hourly-prune")
		if err := dashboard.PruneHourly(ctx, conn); err != nil && ctx.Err() == nil {
			log.Printf("hourly aggregate prune: %v", err)
		}
	}
	runAgg()
	runPrune()
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	pruneDue := false
	for n := 0; tick(ctx, t); n++ {
		if n%60 == 0 {
			pruneDue = true
		}
		// A schema update holds the write lock: every statement
		// here would wait out the busy timeout and fail.  The
		// rollups continue from their cursors and the prune from
		// its cutoff, so a skipped turn costs nothing but time.
		if conn.WritesHeld() {
			continue
		}
		runAgg()
		if pruneDue {
			pruneDue = false
			runPrune()
		}
	}
}
