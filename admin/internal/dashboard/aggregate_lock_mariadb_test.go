package dashboard

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// mariadbSettingsFromEnv mirrors internal/db's docker-gated helper (package
// private there).  Skips unless `make test-mariadb` set the environment.
func mariadbSettingsFromEnv(t *testing.T) settings.DB {
	t.Helper()
	host := os.Getenv("UNMASK_TEST_MARIADB_HOST")
	if host == "" {
		t.Skip("UNMASK_TEST_MARIADB_HOST not set; run `make test-mariadb` for a containerized MariaDB")
	}
	port := 3306
	if p := os.Getenv("UNMASK_TEST_MARIADB_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	envOr := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	return settings.DB{
		Driver: string(db.DriverMariaDB),
		MariaDB: settings.MariaDB{
			Host:     host,
			Port:     port,
			User:     envOr("UNMASK_TEST_MARIADB_USER", "root"),
			Password: os.Getenv("UNMASK_TEST_MARIADB_PASSWORD"),
			Database: envOr("UNMASK_TEST_MARIADB_DATABASE", "unmask_test"),
		},
	}
}

// TestMariaDB_ConcurrentAggregatePassesCountOnce: two daemons on one MariaDB
// fold at the same moment, round after round, and every event is in the
// rollup once.  Without the aggregate lock both passes read the cursor before
// either moved it, folded the same events, and each added its counts to the
// other's.
//
// A pass that finds the lock taken folds nothing (the holder has that turn),
// so a round ends with one more pass on its own: what is checked is the
// rollup once everything written has been folded.
func TestMariaDB_ConcurrentAggregatePassesCountOnce(t *testing.T) {
	cfg := mariadbSettingsFromEnv(t)
	open := func() *db.DB {
		t.Helper()
		d, err := db.Open(cfg)
		if err != nil {
			t.Fatalf("open mariadb: %v", err)
		}
		t.Cleanup(func() { d.Close() })
		return d
	}
	one, two := open(), open() // two daemons: two pools on one database
	if err := db.Migrate(one); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	// The container's database is shared across the TestMariaDB_* suite:
	// start from no events, no rollup and no cursor.
	for _, q := range []string{
		`DELETE FROM unmask_event`,
		`DELETE FROM unmask_aggregate_hourly`,
		`DELETE FROM unmask_aggregate_hll`,
		`DELETE FROM unmask_aggregate_state WHERE name = '` + hourlyState + `'`,
	} {
		if _, err := one.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	defer hourlyReady.Store(false)
	// Every pass folds what it can see: the settling of hourlyFence is the
	// subject of TestMariaDB_HourlyFoldWaitsForALateCommit.
	settleNothing(t)

	written := 0
	write := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			written++
			if err := events.Insert(ctx, one, &events.Event{
				Site: "lock.example", Phase: "serve",
				IPPacked: events.PackIP(fmt.Sprintf("203.0.113.%d", written%250+1)),
			}); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
	}
	folded := func() int {
		t.Helper()
		var n int
		if err := one.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(cnt), 0) FROM unmask_aggregate_hourly WHERE bucket_kind = ? AND bucket_key = ?`,
			hkPhase, "serve").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	for round := 1; round <= 6; round++ {
		write(400)
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, d := range []*db.DB{one, two} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = AggregateHourly(ctx, d, nil)
			}()
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d, daemon %d: %v", round, i+1, err)
			}
		}
		if err := AggregateHourly(ctx, two, nil); err != nil {
			t.Fatalf("round %d, the pass on its own: %v", round, err)
		}
		if got := folded(); got != written {
			t.Fatalf("round %d: the rollup holds %d serve events, %d were written", round, got, written)
		}
	}
}

// settleNothing lets every pass of the test fold every id it can see, as the
// fold did before hourlyFence, and forgets the sightings of earlier tests.
func settleNothing(t *testing.T) {
	t.Helper()
	old := hourlySettle
	hourlySettle = 0
	hourlySeen = seenIDs{}
	t.Cleanup(func() { hourlySettle = old; hourlySeen = seenIDs{} })
}

// TestMariaDB_HourlyFoldWaitsForALateCommit: an event whose transaction
// commits after one with a higher id is still counted.  A batch holds its
// ids from its INSERT to its COMMIT; a beacon written meanwhile takes the
// next id and is seen first.  A fold in that moment used to fold the beacon,
// move the cursor past the batch's id, and never count the batch.  Now a
// pass folds only up to the MAX(id) it saw hourlySettle before, so the first
// pass folds nothing and the next one counts both.
func TestMariaDB_HourlyFoldWaitsForALateCommit(t *testing.T) {
	cfg := mariadbSettingsFromEnv(t)
	d, err := db.Open(cfg)
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	for _, q := range []string{
		`DELETE FROM unmask_event`,
		`DELETE FROM unmask_aggregate_hourly`,
		`DELETE FROM unmask_aggregate_hll`,
		`DELETE FROM unmask_aggregate_state WHERE name = '` + hourlyState + `'`,
	} {
		if _, err := d.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	defer hourlyReady.Store(false)
	now := time.Date(2026, 11, 24, 4, 0, 0, 0, time.UTC)
	oldNow, oldSettle := hourlyNow, hourlySettle
	hourlyNow, hourlySettle, hourlySeen = func() time.Time { return now }, 30*time.Second, seenIDs{}
	t.Cleanup(func() { hourlyNow, hourlySettle, hourlySeen = oldNow, oldSettle, seenIDs{} })

	serves := func() int {
		t.Helper()
		var n int
		if err := d.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(cnt), 0) FROM unmask_aggregate_hourly WHERE bucket_kind = ? AND bucket_key = ?`,
			hkPhase, "serve").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// The batch: its row has its id, and is not committed yet.
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO unmask_event (site, ip_address, phase, date_created) VALUES (?, ?, ?, ?)`,
		"late.example", events.PackIP("203.0.113.7"), "serve", now); err != nil {
		t.Fatalf("the batch's insert: %v", err)
	}
	// The beacon: the next id, committed at once.
	if err := events.Insert(ctx, d, &events.Event{Site: "late.example", Phase: "serve", IPPacked: events.PackIP("203.0.113.8")}); err != nil {
		t.Fatalf("the beacon's insert: %v", err)
	}
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	if n := serves(); n != 0 {
		t.Fatalf("the first pass folded %d serve(s) before any id had settled", n)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("the batch's commit: %v", err)
	}

	now = now.Add(time.Minute)
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("the next pass: %v", err)
	}
	if n := serves(); n != 2 {
		t.Fatalf("the rollup holds %d serve(s); the batch committed late and the beacon make 2", n)
	}
}
