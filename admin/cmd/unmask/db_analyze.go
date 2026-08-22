// db-analyze: refresh the SQLite query planner's index statistics (sqlite_stat1).
//
// Without them SQLite cannot estimate how selective `date_created > ?` is, so the
// stats and bot-hunt pages answer their GROUP BY / DISTINCT over unmask_event by
// scanning a whole covering index -- a cost that grows with the total number of
// stored events instead of the window being viewed.  Measured on a
// multi-million-event node: the verdict-distribution card drops from 2.2s to
// 0.24s and the host
// filter list from 0.95s to under a millisecond once the statistics exist.
//
// This is a MAINTENANCE command, not something the daemon should do: ANALYZE
// holds a write transaction for its entire run (60-70s on a 3.4GB database),
// during which event inserts fail with SQLITE_BUSY.  Run it while traffic is low,
// or right after an install/upgrade.  The statistics persist, so once is enough
// until the table grows by an order of magnitude.
//
// Usage:
//
//	unmask db-analyze                  # config.yml from the default path
//	unmask db-analyze -config PATH
package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

func cmdDBAnalyze(args []string) error {
	fs := flag.NewFlagSet("db-analyze", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	timeout := fs.Duration("timeout", 10*time.Minute, "abort if ANALYZE takes longer than this")
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

	if conn.Driver != db.DriverSQLite {
		fmt.Println("db-analyze: nothing to do (MariaDB/MySQL maintains its own index statistics)")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	had, _ := conn.HasPlannerStats(ctx)
	fmt.Println("db-analyze: ANALYZE takes a write lock for its whole run; on a multi-GB")
	fmt.Println("            database that is a minute or so, and event inserts will block.")
	if had {
		fmt.Println("            (statistics already exist; this refreshes them)")
	}

	t0 := time.Now()
	if err := conn.RefreshPlannerStats(ctx); err != nil {
		return fmt.Errorf("analyze: %w", err)
	}
	fmt.Printf("db-analyze: statistics refreshed in %v\n", time.Since(t0).Round(time.Millisecond))
	return nil
}
