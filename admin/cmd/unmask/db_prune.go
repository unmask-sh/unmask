package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// cmdDBPrune: `unmask db-prune` -- clear an events backlog while the daemon is
// stopped, or run the daemon's paced prune once from the shell.
//
// The daemon prunes hourly in paced chunks and keeps up on any install where
// it ran that way from the start.  An install that grew a backlog first (the
// prune could not keep up, or retention was lowered by weeks) is better
// served offline: with nobody else writing there is no lock to yield, and
// "rebuild" copies the rows to keep into a fresh table instead of deleting
// the rest one by one -- minutes where deletes take hours on a large file.
func cmdDBPrune(args []string) error {
	fs := flag.NewFlagSet("db-prune", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	retention := fs.Int("retention-days", 0, "keep this many days (default: events_retention_days from the config)")
	mode := fs.String("mode", "delete", "delete: remove old rows in chunks | rebuild: copy the rows to keep into a new table and drop the rest (SQLite, offline only)")
	vacuum := fs.Bool("vacuum", false, "VACUUM afterwards to give the freed space back to the filesystem (SQLite; writes a copy of the live data next to the database first, so needs that much free disk there, and a while)")
	analyze := fs.Bool("analyze", false, "refresh the query-planner statistics afterwards (same as `unmask db-analyze`)")
	force := fs.Bool("force", false, "run even though the daemon answers on its socket (delete mode only: it then paces itself like the daemon's own prune)")
	skipSpace := fs.Bool("skip-space-check", false, "run rebuild / VACUUM even when the free space next to the database looks short")
	timeout := fs.Duration("timeout", 12*time.Hour, "abort if the run takes longer than this")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	days := *retention
	if days <= 0 {
		days = s.EventsRetentionDays
	}
	if days <= 0 {
		return errors.New("db-prune: retention is 0 (nothing expires); pass -retention-days N")
	}
	if *mode != "delete" && *mode != "rebuild" {
		return fmt.Errorf("db-prune: unknown -mode %q (delete|rebuild)", *mode)
	}
	running := daemonAnswers(s.Server)
	if running && (!*force || *mode == "rebuild") {
		hint := "stop it first (systemctl stop unmask / service unmask stop; the site keeps serving, fail-open)"
		if *mode == "delete" {
			hint += ", or pass -force to prune online at the daemon's own pace"
		}
		return fmt.Errorf("db-prune: the daemon is running on %s -- %s", daemonAddr(s.Server), hint)
	}

	// Maintenance open: one connection, temporary storage on disk next to
	// the database.  In memory (the daemon's setting) a VACUUM or an index
	// build over a large table is a copy of the result in RAM.
	conn, err := db.OpenMaintenance(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()
	if *mode == "rebuild" && conn.Driver != db.DriverSQLite {
		return errors.New("db-prune: -mode rebuild is SQLite only (on MariaDB use -mode delete)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	say := func(f string, a ...any) { fmt.Printf("db-prune: "+f+"\n", a...) }
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	say("keeping %d days (rows newer than %s UTC), mode %s, %s", days, cutoff.Format("2006-01-02 15:04"), *mode,
		map[bool]string{true: "online (paced)", false: "offline"}[running])
	// The room a rebuild or a VACUUM needs is next to the database: the new
	// table is written before the old one is dropped, and VACUUM writes a copy
	// of the live data there (OpenMaintenance points the temp store at that
	// directory).  Said up front, and checked before each step.
	var dbDir string
	var free int64
	haveFree := false
	if conn.Driver == db.DriverSQLite && s.DB.SQLitePath != "" {
		if st, err := os.Stat(s.DB.SQLitePath); err == nil {
			say("file %s is %s before", s.DB.SQLitePath, humanBytesCLI(st.Size()))
		}
		dbDir = filepath.Dir(s.DB.SQLitePath)
		if f, err := db.DirFree(dbDir); err == nil {
			free, haveFree = f, true
			say("temporary files and the rebuilt table go to %s (%s free)", dbDir, humanBytesCLI(free))
		} else {
			say("cannot read the free space of %s: %v", dbDir, err)
		}
	}
	room := func(step string, need int64) error {
		if !haveFree || *skipSpace || !spaceShort(need, free) {
			return nil
		}
		return fmt.Errorf("db-prune: %s needs about %s free in %s and %s is available; free some space (or pass -skip-space-check to go ahead anyway)",
			step, humanBytesCLI(spaceWithMargin(need)), dbDir, humanBytesCLI(free))
	}

	t0 := time.Now()
	switch *mode {
	case "delete":
		last := time.Now()
		res, err := events.PruneOldEventsOpts(ctx, conn, days, events.PruneOptions{
			Offline: !running,
			Progress: func(r events.PruneResult) {
				if time.Since(last) >= 10*time.Second {
					last = time.Now()
					say("%d rows deleted in %d chunks (%s elapsed, %d busy retries)", r.Deleted, r.Chunks, time.Since(t0).Round(time.Second), r.BusyRetries)
				}
			},
		})
		if err != nil {
			return fmt.Errorf("db-prune: %w (%d rows deleted first; run again to continue)", err, res.Deleted)
		}
		say("deleted %d rows in %d chunks, %v", res.Deleted, res.Chunks, res.Elapsed.Round(time.Millisecond))
	case "rebuild":
		if haveFree {
			kept, total, err := events.RebuildEstimate(ctx, conn, days)
			if err != nil {
				return fmt.Errorf("db-prune: %w", err)
			}
			sp, err := conn.Space(ctx)
			if err != nil {
				return fmt.Errorf("db-prune: %w", err)
			}
			need := int64(0)
			if total > 0 {
				need = int64(float64(sp.LiveBytes) * float64(kept) / float64(total))
			}
			say("rebuild keeps about %d of %d rows (%s of %s live): the new table needs about that much room", kept, total, humanBytesCLI(need), humanBytesCLI(sp.LiveBytes))
			if err := room("rebuild", need); err != nil {
				return err
			}
		}
		res, err := events.RebuildEvents(ctx, conn, days, func(m string) { say("%s", m) })
		if err != nil {
			return fmt.Errorf("db-prune: %w", err)
		}
		say("kept %d rows, %d indexes rebuilt, %v", res.Kept, res.Indexes, res.Elapsed.Round(time.Millisecond))
	}
	if *vacuum && conn.Driver == db.DriverSQLite {
		if haveFree {
			sp, err := conn.Space(ctx)
			if err != nil {
				return fmt.Errorf("db-prune: %w", err)
			}
			if f, err := db.DirFree(dbDir); err == nil {
				free = f
			}
			say("VACUUM writes a copy of the live data (%s of the %s file) to %s (%s free)", humanBytesCLI(sp.LiveBytes), humanBytesCLI(sp.FileBytes), dbDir, humanBytesCLI(free))
			if err := room("VACUUM", sp.LiveBytes); err != nil {
				return err
			}
		}
		say("VACUUM (rewrites the file; this takes a while on a large database)")
		t1 := time.Now()
		if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
			return fmt.Errorf("db-prune: vacuum: %w", err)
		}
		say("VACUUM done in %v", time.Since(t1).Round(time.Millisecond))
	}
	if *analyze {
		t1 := time.Now()
		if err := conn.RefreshPlannerStats(ctx); err != nil {
			return fmt.Errorf("db-prune: analyze: %w", err)
		}
		say("planner statistics refreshed in %v", time.Since(t1).Round(time.Millisecond))
	}
	if conn.Driver == db.DriverSQLite && s.DB.SQLitePath != "" {
		if st, err := os.Stat(s.DB.SQLitePath); err == nil {
			say("file %s is %s after", s.DB.SQLitePath, humanBytesCLI(st.Size()))
		}
	}
	if !running {
		say("done; start the daemon again (systemctl start unmask / service unmask start)")
	}
	return nil
}

// daemonAnswers reports whether something accepts connections where the
// daemon is configured to listen -- the daemon itself, in practice.
func daemonAnswers(srv settings.Server) bool {
	addr := daemonAddr(srv)
	network := "tcp"
	if srv.SocketMode != "" || (addr != "" && addr[0] == '/') {
		network = "unix"
	}
	c, err := net.DialTimeout(network, addr, 700*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// daemonAddr is the daemon's listen address as a dial target.
func daemonAddr(srv settings.Server) string {
	bind := srv.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	if bind[0] == '/' {
		return bind
	}
	port := srv.Port
	if port == 0 {
		port = 9477
	}
	return net.JoinHostPort(bind, strconv.Itoa(port))
}

func humanBytesCLI(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// spaceMargin is the headroom asked for over the bytes a step writes: a
// rebuild's estimate is a share of the live bytes, a VACUUM's copy carries
// its own page overhead, and a filesystem at zero is nobody's plan.
const spaceMargin = 1.1

func spaceWithMargin(need int64) int64 { return int64(float64(need) * spaceMargin) }

// spaceShort: the free space is less than the step needs with its margin.
func spaceShort(need, free int64) bool { return free < spaceWithMargin(need) }
