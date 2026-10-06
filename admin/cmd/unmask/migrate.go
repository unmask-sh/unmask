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
	notice := fs.Bool("notice", false, "print the notice a package upgrade shows when a schema update was left for the operator, or is running (nothing otherwise); used by the package scripts")
	by := fs.String("by", db.SchemaUpdateByCLI, "who started the run, for its record (the admin UI passes the administrator's name)")
	skipSpace := fs.Bool("skip-space-check", false, "build indexes even when the free space next to the database looks short")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		if *notice {
			return nil // a package script must not fail over a notice
		}
		return err
	}
	host := resolveHostID(s.Server.HostID)
	if *notice {
		migrateNotice(s)
		return nil
	}
	if *status && noSQLiteFile(s.DB) {
		fmt.Println("schema: not created yet (a new database); `unmask migrate`, or the setup wizard, creates it")
		return nil
	}

	conn, err := db.Open(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()

	if *status {
		return migrateStatus(conn, s)
	}
	if *startup {
		return migrateStartup(conn, s)
	}

	// The output goes to a terminal, or to the daemon that started this run
	// as its child.  If that daemon goes away, its end of the pipe goes with
	// it, and the next line written would end the run by SIGPIPE halfway,
	// with no record of how it ended: a lost line is better than that.
	signal.Ignore(syscall.SIGPIPE)
	// An interrupt, a terminal hung up, a stop: the statement that is
	// running is cancelled (SQLite rolls a cancelled index build back,
	// MariaDB's is killed on the server) and the update is simply still
	// pending.  A second signal ends the process at once.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()

	say := func(f string, a ...any) { fmt.Printf("migrate: "+f+"\n", a...) }
	res, err := db.ApplySchemaUpdate(ctx, conn, db.SchemaUpdateOptions{
		Host: host, By: *by, SkipSpaceCheck: *skipSpace,
		Logf:   func(f string, a ...any) { say("%s", strings.TrimPrefix(fmt.Sprintf(f, a...), "db: ")) },
		Finish: func(c context.Context) error { return migrateFinish(c, conn, s) },
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return errors.New("interrupted; the schema update is still pending and can be run again")
		}
		return err
	}
	if n := len(res.Applied); n > 0 && res.Elapsed >= time.Second {
		fmt.Printf("schema applied (%d update(s) in %s)\n", n, res.Elapsed.Round(time.Second))
	} else {
		fmt.Println("schema applied")
	}
	if res.FinishErr != nil {
		return res.FinishErr
	}
	return nil
}

// migrateStartup is the daemon's own pass, run ahead of it by the container
// entrypoint.  A container has no package script to create the schema before
// the first start, and its supervisor gives the daemon a fixed time to come
// up: an index build over a large table run here would use that time up, the
// container would be restarted, and the build would begin again.  So builds
// are estimated as reads from disk (a start may follow a reboot, with nothing
// cached), and what is left is announced.
//
// What follows the migrations is not the daemon's to do at all (serve does
// not gather the planner's statistics), so its failure is a warning here: one
// that meets a schema update's write lock -- a run the daemon started, still
// going after the daemon itself was restarted -- must not keep the daemon
// from starting.
func migrateStartup(conn *db.DB, s settings.Settings) error {
	res, err := db.MigrateWith(conn, db.MigrateOptions{
		Defer: true, DeferOver: s.DB.SchemaUpdateDeferOver(), ColdCache: true,
		Logf: func(f string, a ...any) {
			fmt.Printf("migrate: %s\n", strings.TrimPrefix(fmt.Sprintf(f, a...), "db: "))
		},
	})
	if err != nil {
		return err
	}
	fmt.Println("schema applied")
	if len(res.Deferred) > 0 {
		fmt.Print(schemaNotice(res.Deferred, conn.SchemaUpdateHoldsWrites(), "unmask migrate   (in the container)", fileSpace(conn)))
	}
	if err := migrateFinish(context.Background(), conn, s); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: warning: %v (done by the next `unmask migrate`)\n", err)
	}
	return nil
}

// noSQLiteFile reports whether the database is SQLite and its file does not
// exist: a new install, where a command that only reports must not create it.
func noSQLiteFile(d settings.DB) bool {
	if d.Driver != "" && d.Driver != string(db.DriverSQLite) {
		return false
	}
	_, err := os.Stat(d.SQLitePath)
	return errors.Is(err, os.ErrNotExist)
}

// migrateFinish is what follows the schema in every run that applies one: the
// planner's statistics, on a database small enough to gather them in a moment.
//
// It used to backfill ja4_verdict_id first, an UPDATE per verdict name that
// walked every event of that verdict and read each row to find the ones
// without an id.  The column dates from long ago and every event is written
// with its id since (the daemon and nginx share one verdict registry, so a
// name cannot reach an event before its id exists), so the walk found nothing
// -- and on a large, fragmented database took over twenty minutes of random
// reads after the index, with the daemon's writes held, saying nothing, and
// deaf to an interrupt (a large install, 2026-10-06).  Gone.
//
// An interrupt stops the statistics too.  The schema is applied by then, so
// that is no failure: seedPlannerStats says they were not built, and doctor
// says so until `unmask db-analyze` builds them.
func migrateFinish(ctx context.Context, conn *db.DB, s settings.Settings) error {
	seedPlannerStats(ctx, conn, s.DB)
	return nil
}

// noticeTimeout bounds `migrate -notice`.  It runs in a package script,
// before the daemon is restarted, and the package manager waits for it: a
// MariaDB that does not answer must not stand the upgrade still.  A variable
// for the test that proves it.
var noticeTimeout = 10 * time.Second

// migrateNotice prints what a package upgrade shows about the schema: an
// update the new daemon will leave for the operator, or one that is running
// now -- and nothing at all otherwise, which is nearly every upgrade.  It
// never fails, never creates a database, and gives up quietly after
// noticeTimeout; the daemon's log and the admin UI say the same.
func migrateNotice(s settings.Settings) {
	if noSQLiteFile(s.DB) {
		return // a new install: there is nothing to update
	}
	if s.DB.Driver == "" || s.DB.Driver == string(db.DriverSQLite) {
		// Opened here, a large write-ahead log is replayed -- minutes for
		// every few GB -- and, the daemon being stopped, checkpointed when
		// this closes it.  Not in a package script.
		if st, err := os.Stat(s.DB.SQLitePath + "-wal"); err == nil && st.Size() >= db.WALLargeBytes {
			return
		}
	}
	out := make(chan string, 1)
	go func() { out <- noticeText(s) }()
	select {
	case text := <-out:
		fmt.Print(text)
	case <-time.After(noticeTimeout):
	}
}

// noticeText works out migrateNotice's text; "" for nothing to say.
func noticeText(s settings.Settings) string {
	conn, err := db.Open(s.DB)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if has, err := db.HasSchema(conn); err != nil || !has {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if rec, ok, err := conn.LoadSchemaUpdate(ctx); err == nil && ok && conn.SchemaUpdateAlive(ctx, rec, time.Now()) {
		return runningNotice(rec, conn.SchemaUpdateHoldsWrites())
	}
	pending, err := db.PendingMigrations(conn)
	if err != nil {
		return ""
	}
	left := db.LeftForTheOperator(pending, s.DB.SchemaUpdateDeferOver())
	if len(left) == 0 {
		return ""
	}
	return schemaNotice(left, conn.SchemaUpdateHoldsWrites(), "sudo unmask migrate", fileSpace(conn))
}

// runningNotice words a schema update that is running while the package is
// upgraded.  One started from the admin UI is the daemon's child, and the
// restart that follows the upgrade stops it; one started from a shell is not,
// and goes on.
func runningNotice(rec db.SchemaUpdateRecord, holdsWrites bool) string {
	started := time.Unix(rec.StartedAt, 0).UTC().Format("2006-01-02 15:04 UTC")
	var b strings.Builder
	b.WriteString("\n")
	if rec.By == db.SchemaUpdateByCLI {
		fmt.Fprintf(&b, "unmask: a database update is running (`unmask migrate`, started %s on %s).\n", started, rec.Host)
		if holdsWrites {
			b.WriteString("        It goes on while the daemon restarts; the daemon keeps its writes back until it has finished.\n")
		} else {
			b.WriteString("        It goes on while the daemon restarts.\n")
		}
	} else {
		fmt.Fprintf(&b, "unmask: a database update started from the admin UI (by %s, %s) is running.\n", rec.By, started)
		b.WriteString("        The daemon's restart for this upgrade stops it.  Nothing is lost: it waits to be run again,\n")
		b.WriteString("          admin UI  ->  the notice at the top of every page\n")
		b.WriteString("          shell     ->  sudo unmask migrate\n")
	}
	b.WriteString("\n")
	return b.String()
}

// migrateStatus prints what is pending and changes nothing.
func migrateStatus(conn *db.DB, s settings.Settings) error {
	if has, err := db.HasSchema(conn); err == nil && !has {
		fmt.Println("schema: not created yet (a new database); `unmask migrate`, or the setup wizard, creates it")
		return nil
	}
	pending, err := db.PendingMigrations(conn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if rec, ok, err := conn.LoadSchemaUpdate(ctx); err == nil && ok && conn.SchemaUpdateAlive(ctx, rec, time.Now()) {
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
	for _, m := range db.LeftForTheOperator(pending, s.DB.SchemaUpdateDeferOver()) {
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
	if note := scatterNote(pending, fileSpace(conn), "      "); note != "" {
		fmt.Print("note: " + note)
	}
	fmt.Println("apply with:  sudo unmask migrate    (the daemon can keep running: the challenge is served throughout)")
	return nil
}

// fileSpace is the page accounting of a SQLite database, nil for MariaDB or
// when it cannot be read: what scatterNote decides on.
func fileSpace(conn *db.DB) *db.SQLiteSpace {
	if conn.Driver != db.DriverSQLite {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sp, err := conn.Space(ctx)
	if err != nil {
		return nil
	}
	return &sp
}

// scatterNote tells an operator about to run index builds over a scattered
// file (db.SQLiteSpace.Scattered, where doctor advises a compaction) that they
// read the tables a page at a time, and where to see what compacting the file
// first would take.  On a large install (2026-09-29) a build over a file more
// than half free took two and a half times as long as estimated; the estimate
// allows for it now, and the operator may rather compact first.  "" for
// anything else: MariaDB, a compact file, nothing to build.  indent starts
// every line but the first.
func scatterNote(pending []db.PendingMigration, sp *db.SQLiteSpace, indent string) string {
	if sp == nil || !sp.Scattered() {
		return ""
	}
	builds := false
	for _, m := range pending {
		builds = builds || len(m.Indexes) > 0
	}
	if !builds {
		return ""
	}
	return fmt.Sprintf("%s of the %s database file is free space, and the tables lie scattered through it:\n"+
		"%sthe build reads them a page at a time, which takes longer.  Compacting the file first lays them\n"+
		"%sout again: `unmask db-vacuum -plan` shows what that would take.\n",
		humanBytesCLI(sp.FileBytes-sp.LiveBytes), humanBytesCLI(sp.FileBytes), indent, indent)
}

// schemaNotice words the updates a daemon start left out for whoever is
// looking at the terminal of a package upgrade, or at a container's log.
// holdsWrites: the run keeps the daemon's writes out (db.SchemaUpdateHoldsWrites),
// which is worth a line.  shell: the command, as it is typed there.  sp: the
// database file's page accounting (nil for MariaDB), for scatterNote.
func schemaNotice(left []db.PendingMigration, holdsWrites bool, shell string, sp *db.SQLiteSpace) string {
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
	fmt.Fprintf(&b, "          shell     ->  %s\n", shell)
	if holdsWrites {
		b.WriteString("        The challenge is served while it runs; events recorded meanwhile are written afterwards.\n")
	} else {
		b.WriteString("        The challenge is served while it runs.\n")
	}
	if note := scatterNote(left, sp, "        "); note != "" {
		b.WriteString("        " + note)
	}
	b.WriteString("\n")
	return b.String()
}
