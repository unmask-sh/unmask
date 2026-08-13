package db

import (
	"context"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestEventDateIndexHint: SQLite needs the hint (its planner scans the whole
// (ip_address, date_created) covering index for GROUP BY ip_address, even after
// ANALYZE); MariaDB names its indexes differently and estimates the range from
// live InnoDB statistics, so it must stay unhinted.
func TestEventDateIndexHint(t *testing.T) {
	const win = "date_created > 'x'"
	if got := (&DB{Driver: DriverSQLite}).EventDateIndexHint(win); got != " INDEXED BY idx_unmask_event_date" {
		t.Errorf("sqlite hint = %q", got)
	}
	if got := (&DB{Driver: DriverMariaDB}).EventDateIndexHint(win); got != "" {
		t.Errorf("mariadb must be unhinted, got %q", got)
	}
	// No window, no hint: INDEXED BY on a query that cannot use the index is a
	// hard SQLite error, so this guard is the reason the window is a parameter
	// rather than something every caller has to remember.
	for _, d := range []*DB{{Driver: DriverSQLite}, {Driver: DriverMariaDB}} {
		if got := d.EventDateIndexHint(""); got != "" {
			t.Errorf("%s: an unwindowed query must not be pinned, got %q", d.Driver, got)
		}
	}
}

// TestRefreshPlannerStatsPopulatesStat1: a fresh unmask DB ships no sqlite_stat1,
// which is what makes the planner pick a full covering-index scan for the hunt /
// stats GROUP BY + DISTINCT queries.  RefreshPlannerStats must create it, and be
// safe to call repeatedly (`unmask db-analyze` may be re-run on a live DB).
func TestRefreshPlannerStatsPopulatesStat1(t *testing.T) {
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	stat1Rows := func() int {
		var n int
		// sqlite_stat1 does not exist until ANALYZE has run at least once.
		var tbl int
		if err := d.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE name='sqlite_stat1'`).Scan(&tbl); err != nil {
			t.Fatal(err)
		}
		if tbl == 0 {
			return -1
		}
		if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_stat1`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if got := stat1Rows(); got != -1 {
		t.Fatalf("a fresh DB must have no sqlite_stat1 (the bug's precondition), got %d rows", got)
	}
	if ok, err := d.HasPlannerStats(ctx); err != nil || ok {
		t.Fatalf("HasPlannerStats on a fresh DB = (%v, %v); want (false, nil)", ok, err)
	}
	// Some rows so ANALYZE has something to sample.
	for i := 0; i < 50; i++ {
		if _, err := d.ExecContext(ctx,
			`INSERT INTO unmask_event (site, host, ip_address, phase, date_created)
			 VALUES ('s','h', X'0A000001', 'serve', CURRENT_TIMESTAMP)`); err != nil {
			t.Fatal(err)
		}
	}

	if err := d.RefreshPlannerStats(ctx); err != nil {
		t.Fatalf("RefreshPlannerStats: %v", err)
	}
	if got := stat1Rows(); got <= 0 {
		t.Fatalf("sqlite_stat1 must be populated after RefreshPlannerStats, got %d", got)
	}
	if ok, err := d.HasPlannerStats(ctx); err != nil || !ok {
		t.Fatalf("HasPlannerStats after ANALYZE = (%v, %v); want (true, nil)", ok, err)
	}
	// Idempotent: `unmask db-analyze` may be re-run on a live DB.
	if err := d.RefreshPlannerStats(ctx); err != nil {
		t.Fatalf("RefreshPlannerStats (2nd): %v", err)
	}
	if got := stat1Rows(); got <= 0 {
		t.Fatalf("sqlite_stat1 must survive a repeat run, got %d", got)
	}
}

// TestHasPlannerStatsMariaDB: InnoDB keeps its own statistics, so the check must
// report "present" without touching the connection.
func TestHasPlannerStatsMariaDB(t *testing.T) {
	ok, err := (&DB{Driver: DriverMariaDB}).HasPlannerStats(context.Background())
	if err != nil || !ok {
		t.Errorf("mariadb HasPlannerStats = (%v, %v); want (true, nil)", ok, err)
	}
}

// TestRefreshPlannerStatsMariaDBNoop: the pragmas are SQLite-only; on MariaDB the
// call must be a silent no-op rather than sending invalid SQL to the server.
func TestRefreshPlannerStatsMariaDBNoop(t *testing.T) {
	// No connection is dialled: a non-SQLite driver returns before touching it.
	d := &DB{Driver: DriverMariaDB}
	if err := d.RefreshPlannerStats(context.Background()); err != nil {
		t.Errorf("mariadb RefreshPlannerStats must be a no-op, got %v", err)
	}
}
