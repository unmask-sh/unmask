package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// cmdMigrate: `unmask migrate` -- create the schema on a new database, and
// apply whatever schema updates are pending on an existing one.
//
// That includes the updates the daemon does not apply by itself.  Building an
// index over a large events table takes minutes, and the daemon migrates
// before it listens, so it leaves such a build for the operator (see
// internal/db/migrator.go) and says so: in its log, in `unmask doctor`, in a
// notice at the top of the admin UI, and in the lines a package upgrade
// prints.  This command is how it is then applied -- typed into a shell, or
// started by the daemon when an administrator presses the button in that
// notice; both are this same code.
//
// The daemon can keep running.  While an index is built SQLite's write lock
// is held, so the daemon serves the challenge as before, keeps the events it
// cannot write and writes them afterwards.
func cmdMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	status := fs.Bool("status", false, "list the schema updates that are pending, with how long each is expected to take, and change nothing")
	startup := fs.Bool("startup", false, "apply what a start of the daemon applies: everything but the index builds it leaves for the operator, which are announced instead (the container entrypoint runs this before the daemon)")
	notice := fs.Bool("notice", false, "print the notice a package upgrade shows when a schema update was left for the operator (nothing when none was); used by the package scripts")
	by := fs.String("by", db.SchemaUpdateByCLI, "who started the run, for its record (the admin UI passes the administrator's name)")
	skipSpace := fs.Bool("skip-space-check", false, "build indexes even when the free space next to the database looks short")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()
	host := resolveHostID(s.Server.HostID)

	if *status || *notice {
		return migrateReport(conn, s, host, *notice)
	}
	if *startup {
		// The daemon's own pass, run ahead of it.  A container has no
		// package script to create the schema before the first start, and
		// its supervisor gives the daemon a fixed time to come up: an index
		// build over a large table run here would use that time up, the
		// container would be restarted, and the build would begin again.
		res, err := db.MigrateWith(conn, db.MigrateOptions{
			Defer: true, DeferOver: s.DB.SchemaUpdateDeferOver(),
			Logf: func(f string, a ...any) {
				fmt.Printf("migrate: %s\n", strings.TrimPrefix(fmt.Sprintf(f, a...), "db: "))
			},
		})
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		fmt.Println("schema applied")
		if len(res.Deferred) > 0 {
			fmt.Print(schemaNotice(res.Deferred, conn.SchemaUpdateHoldsWrites()))
		}
		return migrateFinish(conn, s)
	}

	// An interrupt cancels the statement that is running.  SQLite rolls a
	// cancelled index build back, so the update is simply still pending.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	say := func(f string, a ...any) { fmt.Printf("migrate: "+f+"\n", a...) }
	res, err := db.ApplySchemaUpdate(ctx, conn, db.SchemaUpdateOptions{
		Host: host, By: *by, SkipSpaceCheck: *skipSpace,
		Logf: func(f string, a ...any) { say("%s", strings.TrimPrefix(fmt.Sprintf(f, a...), "db: ")) },
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("migrate: interrupted; the schema update is still pending and can be run again")
		}
		return fmt.Errorf("migrate: %w", err)
	}
	if n := len(res.Applied); n > 0 && res.Elapsed >= time.Second {
		fmt.Printf("schema applied (%d update(s) in %s)\n", n, res.Elapsed.Round(time.Second))
	} else {
		fmt.Println("schema applied")
	}
	return migrateFinish(conn, s)
}

// migrateFinish is what follows the schema in every run that applies one:
// the verdict ids of rows written before they existed, and the planner's
// statistics on a database small enough to gather them in a moment.
func migrateFinish(conn *db.DB, s settings.Settings) error {
	// ID-based linking: backfill ja4_verdict_id for existing rows via name lookup.
	// Build the preset registry from built-in + settings.Extra.
	extras := make([]nginxconf.ExtraVerdict, 0, len(s.Nginx.JA4Verdicts.Extra))
	for _, e := range s.Nginx.JA4Verdicts.Extra {
		extras = append(extras, nginxconf.ExtraVerdict{
			ID: e.ID, Verdict: e.Verdict, Action: e.Action, Pattern: e.Pattern,
		})
	}
	reg := nginxconf.BuildVerdictRegistry(extras)
	nameToID := reg.AllNameToID()
	if n, err := db.BackfillVerdictIDs(conn, nameToID); err != nil {
		return fmt.Errorf("backfill verdict id: %w", err)
	} else if n > 0 {
		fmt.Printf("backfilled ja4_verdict_id for %d row(s)\n", n)
	}
	seedPlannerStats(conn, s.DB)
	return nil
}

// migrateReport prints what is pending and changes nothing.  With notice set
// it prints only what a daemon start leaves for the operator, worded for
// someone who has just upgraded the package, and nothing at all when there is
// no such update -- which is every upgrade of a small install.
func migrateReport(conn *db.DB, s settings.Settings, host string, notice bool) error {
	if has, err := db.HasSchema(conn); err == nil && !has {
		if !notice {
			fmt.Println("schema: not created yet (a new database); `unmask migrate`, or the setup wizard, creates it")
		}
		return nil
	}
	pending, err := db.PendingMigrations(conn)
	if err != nil {
		if notice {
			// A package script must not fail, or print a scare, because the
			// database could not be read this once: the daemon's log and the
			// admin UI carry the same notice.
			return nil
		}
		return fmt.Errorf("migrate: %w", err)
	}
	left := db.LeftForTheOperator(pending, s.DB.SchemaUpdateDeferOver())
	if notice {
		if len(left) > 0 {
			fmt.Print(schemaNotice(left, conn.SchemaUpdateHoldsWrites()))
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if rec, ok, err := conn.LoadSchemaUpdate(ctx); err == nil && ok && rec.Alive(host, time.Now()) {
		fmt.Printf("schema: an update is running (started %s by %s on %s, pid %d, %s)\n",
			time.Unix(rec.StartedAt, 0).UTC().Format("2006-01-02 15:04 UTC"), rec.By, rec.Host, rec.PID,
			"expected to take "+db.EstimateRange(time.Duration(rec.EstLowSec)*time.Second, time.Duration(rec.EstHighSec)*time.Second))
		return nil
	}
	if len(pending) == 0 {
		fmt.Println("schema: up to date")
		return nil
	}
	waiting := map[int]bool{}
	for _, m := range left {
		waiting[m.Version] = true
	}
	fmt.Printf("schema: %d update(s) pending\n", len(pending))
	for _, m := range pending {
		who := "applied when the daemon starts"
		if waiting[m.Version] {
			who = "waits for you: the daemon does not apply it at startup"
		}
		fmt.Printf("  %-32s %s  (%s)\n", m.Name, m.Describe(), who)
	}
	fmt.Println("apply with:  unmask migrate    (the daemon can keep running: the challenge is served throughout)")
	return nil
}

// schemaNotice words the updates a daemon start left out for whoever is
// looking at the terminal of a package upgrade.  holdsWrites: the run keeps
// the daemon's writes out (db.SchemaUpdateHoldsWrites), which is worth a line.
func schemaNotice(left []db.PendingMigration, holdsWrites bool) string {
	var low, high time.Duration
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("unmask: a database update is waiting and was NOT applied automatically:\n")
	for _, m := range left {
		low, high = low+m.EstLow, high+m.EstHigh
		if len(m.Indexes) == 0 {
			continue // nothing to build; it only waits to keep its place in the order
		}
		fmt.Fprintf(&b, "          %s  (%s)\n", m.Name, m.Describe())
	}
	fmt.Fprintf(&b, "        The daemon runs normally without it.  Apply it when it suits you (%s):\n", db.EstimateRange(low, high))
	b.WriteString("          admin UI  ->  the notice at the top of every page\n")
	b.WriteString("          shell     ->  unmask migrate\n")
	if holdsWrites {
		b.WriteString("        The challenge is served while it runs; events recorded meanwhile are written afterwards.\n")
	} else {
		b.WriteString("        The challenge is served while it runs.\n")
	}
	b.WriteString("\n")
	return b.String()
}
