package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// cmdDBVacuum: `unmask db-vacuum` -- compact the SQLite database while the
// daemon keeps serving.
//
// VACUUM gives the pages the retention prune freed back to the filesystem and
// lays every table out in order again, which is what a large, long-pruned
// database needs for a full scan to read the disk in order.  It holds the
// write lock for as long as it runs, so the daemon stops writing meanwhile:
// it serves the challenge as before and keeps its events, counters,
// automatic bans and audit rows in memory until the run ends (see
// internal/db/vacuum.go).  Typed into a shell, or started by the daemon when
// an administrator presses the button on the retention tab; both are this
// same code.
//
// `unmask db-prune -vacuum` compacts too, with the daemon stopped -- and the
// site unprotected (fail-open) for as long as it runs.
func cmdDBVacuum(args []string) error {
	fs := flag.NewFlagSet("db-vacuum", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	planOnly := fs.Bool("plan", false, "print what a compaction would give back and need -- disk, time, the events the daemon holds meanwhile -- and change nothing")
	by := fs.String("by", db.VacuumByCLI, "who started the run, for its record (the admin UI passes the administrator's name)")
	skipSpace := fs.Bool("skip-space-check", false, "run even when the free space next to the database looks short of what the copy and its write-back need")
	force := fs.Bool("force", false, "run even when there is little to give back, or the daemon is expected to hold more events than it keeps (the oldest over the limit are then dropped)")
	waitHeld := fs.Duration("wait-held", 15*time.Second, "how long to wait for the running daemon to stop writing before giving up")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	if s.DB.Driver != "" && s.DB.Driver != string(db.DriverSQLite) {
		fmt.Println("db-vacuum: nothing to do: " + db.ErrVacuumSQLiteOnly.Error())
		return nil
	}
	if noSQLiteFile(s.DB) {
		return errors.New("db-vacuum: there is no database file yet")
	}
	// A maintenance connection: VACUUM's copy of the whole database goes to
	// a temporary file next to it, not into memory.
	conn, err := db.OpenMaintenance(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()

	say := func(f string, a ...any) { fmt.Printf("db-vacuum: "+f+"\n", a...) }
	pctx, pcancel := context.WithTimeout(context.Background(), 30*time.Second)
	plan, err := conn.PlanVacuum(pctx)
	pcancel()
	if err != nil {
		return fmt.Errorf("db-vacuum: %w", err)
	}
	printVacuumPlan(say, plan)
	if *planOnly {
		return nil
	}
	if !*force {
		if !plan.Worth() {
			return fmt.Errorf("db-vacuum: only %s of the %s file is free space; a compaction holds the daemon's writes for its whole length and would give back little (pass -force to run anyway)",
				humanBytesCLI(plan.Reclaim), humanBytesCLI(plan.FileBytes))
		}
		if plan.HeldOver() {
			return fmt.Errorf("db-vacuum: the daemon would hold about %d events over the run, more than the %d it keeps; run it at a quieter time, or pass -force (the oldest over the limit are dropped)",
				plan.HeldEvents, plan.HeldLimit)
		}
	}

	// As `unmask migrate`: a lost output line (the daemon that started this
	// run went away) is better than a SIGPIPE halfway; a signal cancels the
	// VACUUM, which SQLite rolls back, and a second one ends the process.
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()

	var wait func(context.Context) error
	if daemonAnswers(s.Server) {
		addr := daemonAddr(s.Server)
		say("the daemon on %s is running: waiting for it to stop writing", addr)
		wait = func(ctx context.Context) error {
			deadline := time.Now().Add(*waitHeld)
			for !conn.VacuumHeldFor(os.Getpid()) {
				if time.Now().After(deadline) {
					return fmt.Errorf("the daemon on %s did not stop writing within %s -- it may be older than this command (restart it on this version), or busy; nothing was changed",
						addr, *waitHeld)
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(100 * time.Millisecond):
				}
			}
			say("the daemon has stopped writing; it keeps serving meanwhile")
			return nil
		}
	}

	res, err := db.RunVacuum(ctx, conn, db.VacuumOptions{
		Host: resolveHostID(s.Server.HostID), By: *by, SkipSpaceCheck: *skipSpace,
		Logf: func(f string, a ...any) { say(f, a...) }, WaitHeld: wait,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return errors.New("db-vacuum: interrupted; the database is as it was")
		}
		return fmt.Errorf("db-vacuum: %w", err)
	}
	say("done: the file went from %s to %s in %s", humanBytesCLI(res.FileBefore), humanBytesCLI(res.FileAfter), res.Elapsed.Round(time.Second))
	return nil
}

// printVacuumPlan says what a compaction gives back and needs.
func printVacuumPlan(say func(string, ...any), p db.VacuumPlan) {
	say("file %s -> about %s after compaction (%s less)", humanBytesCLI(p.FileBytes), humanBytesCLI(p.LiveBytes), humanBytesCLI(p.Reclaim))
	free := "unknown"
	if p.DiskFree >= 0 {
		free = humanBytesCLI(p.DiskFree)
	}
	say("needs about %s free next to the database for the copy and its write-back, given back at the end (%s free)",
		humanBytesCLI(p.DiskNeed), free)
	from := map[string]string{
		"measured": "this host's last compaction",
		"index":    "this host's last index build",
		"default":  "the built-in range; the first run records this host's own",
	}[p.EstFrom]
	say("expected to take %s (from %s)", db.EstimateRange(p.EstLow, p.EstHigh), from)
	say("the daemon keeps serving meanwhile, and holds its writes: about %d events an hour here, up to %d over the run -- about %s of memory, and at most %s of access-log counters besides (it keeps up to %d events)",
		p.EventsPerHour, p.HeldEvents, humanBytesCLI(p.HeldBytes), humanBytesCLI(p.CountersBytes), p.HeldLimit)
}
