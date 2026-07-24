// Package db: SQLite / MariaDB layer with a GORM handle for CRUD.
//
// Hybrid by design: aggregation reads stay raw SQL via the embedded *sql.DB
// (the dashboard queries read more clearly that way), while CRUD increasingly
// goes through GORM models on the Gorm handle (parameterized + type-safe).
// Both share one connection pool -- Gorm.DB() is the embedded *sql.DB.
//
// Pure-Go static binary is preserved: the SQLite driver is glebarez/sqlite
// (modernc-based), NOT the CGO gorm.io/driver/sqlite.
//
// Driver differences:
//   - placeholder: SQLite uses ?, MariaDB also takes ? (database/sql standard),
//     so we use ? for both.
//   - "N minutes ago" SQL fragments differ per driver; generate via NowMinusMinutes().
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	glsqlite "github.com/glebarez/sqlite"
	mysql "github.com/go-sql-driver/mysql"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

type Driver string

const (
	DriverSQLite  Driver = "sqlite"
	DriverMariaDB Driver = "mariadb"
)

type DB struct {
	*sql.DB
	Gorm   *gorm.DB
	Driver Driver
}

// Open returns a configured *DB. SQLite path's parent directory is created if
// missing (so first-run "just works").
func Open(s settings.DB) (*DB, error) {
	var (
		dialector gorm.Dialector
		driver    Driver
		maxIdle   = 4
		maxLife   = time.Hour
	)

	switch s.Driver {
	case "", string(DriverSQLite):
		if err := os.MkdirAll(filepath.Dir(s.SQLitePath), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir sqlite parent: %w", err)
		}
		// _pragma=... = WAL + busy timeout.  Prevents challenge-write vs dashboard-read contention.
		dsn := s.SQLitePath +
			"?_pragma=journal_mode(WAL)" +
			"&_pragma=synchronous(NORMAL)" +
			"&_pragma=busy_timeout(5000)" +
			"&_pragma=cache_size(-131072)" + // -131072 = 128MB page cache: production event DBs run
			// multi-GB (tool1-us ~6GB), where 20MB thrashed on every
			// cold hunt/stats scan; 128MB is still modest next to the
			// 256MB mmap below and pages are evicted under memory pressure
			"&_pragma=temp_store(MEMORY)" + // keep temp tables in memory
			"&_pragma=mmap_size(268435456)" // 256MB mmap to speed up page reads
		dialector = glsqlite.Open(dsn)
		driver = DriverSQLite

	case string(DriverMariaDB):
		cfg := mysql.NewConfig()
		cfg.User = s.MariaDB.User
		cfg.Passwd = s.MariaDB.Password
		cfg.Net = "tcp"
		cfg.Addr = fmt.Sprintf("%s:%d", s.MariaDB.Host, s.MariaDB.Port)
		cfg.DBName = s.MariaDB.Database
		cfg.ParseTime = true
		// Force everything timestamp-related to UTC: the driver-side parse
		// location AND the session time_zone.  With this, NOW() / CURRENT_TIMESTAMP
		// / DATE(col) / DATE_FORMAT(col,…) / DATE_SUB(NOW(),…) all evaluate in
		// UTC, matching SQLite's UTC-by-default behaviour.  The application
		// (= dashboard.Daily*) then converts UTC unix sec to the operator's
		// cookie TZ on read, so the storage is timezone-agnostic.
		cfg.Loc = time.UTC
		cfg.Params = map[string]string{
			"charset":   "utf8mb4",
			"time_zone": "'+00:00'",
		}
		dialector = gormmysql.Open(cfg.FormatDSN())
		driver = DriverMariaDB
		maxIdle = 2
		maxLife = 30 * time.Minute

	default:
		return nil, errors.New("unknown db driver: " + s.Driver)
	}

	gdb, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	conn, err := gdb.DB()
	if err != nil {
		return nil, err
	}
	// WAL mode allows multiple parallel readers; writes are serial (SQLite).
	// Parallelising reads keeps the dashboard from contending with auth_request
	// writes and hitting the busy timeout.
	conn.SetMaxOpenConns(8)
	conn.SetMaxIdleConns(maxIdle)
	conn.SetConnMaxLifetime(maxLife)
	if err := conn.PingContext(context.Background()); err != nil {
		conn.Close()
		return nil, err
	}
	return &DB{DB: conn, Gorm: gdb, Driver: driver}, nil
}

// NowMinusMinutes returns a SQL fragment representing "now - n minutes" for
// the active driver.  Use it inline (= cannot be parameterised client-side).
func (d *DB) NowMinusMinutes(n int) string {
	if d.Driver == DriverSQLite {
		return fmt.Sprintf("datetime('now', '-%d minutes')", n)
	}
	return fmt.Sprintf("DATE_SUB(NOW(), INTERVAL %d MINUTE)", n)
}

// RefreshPlannerStats rebuilds the query planner's index statistics.
//
// SQLite ships NO statistics until ANALYZE runs, and a fresh unmask database
// never runs it.  With no sqlite_stat1 the planner cannot estimate how selective
// `date_created > ?` is, so for a GROUP BY / DISTINCT on a column that has a
// composite (col, date_created) index -- ja4_verdict, site, host, phase -- it
// prefers scanning that whole covering index (avoiding a temp b-tree) over
// seeking the date range.  The query then costs O(all events) rather than
// O(events in the window), which is why the stats and bot-hunt pages get slower
// as events accumulate rather than staying flat.  A sampled ANALYZE flips those
// plans (measured: DISTINCT host 0.22s -> 0.002s, verdict distribution 0.72s ->
// 0.10s on a 1M-row table).
//
// THIS IS A MAINTENANCE OPERATION, NOT A BACKGROUND TASK.  ANALYZE holds a write
// transaction for its whole run, and its run is proportional to the size of the
// indexes: `PRAGMA analysis_limit` only lets it skip runs of DUPLICATE keys, and
// every unmask_event index carries date_created, so they are all near-unique and
// nothing gets skipped.  Measured on tool1-us (3.4GB database, 3.9M events, 1.1GB
// of event indexes): 60-70s, during which every event insert failed with
// SQLITE_BUSY and the challenge beacon's writes took 5s.  On a freshly installed
// database it is instant.  Call it from `unmask db-analyze` or from migrate (the
// service is stopped there) -- never from serve.
//
// analysis_limit is still worth setting: it bounds the per-key sampling and is a
// per-connection setting, so it must run on the SAME connection as ANALYZE --
// hence the explicit Conn.  `PRAGMA optimize` would be lighter, but it only
// considers tables the current connection has already queried, which on a freshly
// checked-out pool connection is none: it would silently do nothing.
//
// MariaDB is a no-op (InnoDB maintains live index statistics itself, and
// estimates the range correctly).
func (d *DB) RefreshPlannerStats(ctx context.Context) error {
	if d.Driver != DriverSQLite {
		return nil
	}
	conn, err := d.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA analysis_limit=400`); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, `ANALYZE`)
	return err
}

// HasPlannerStats reports whether the query planner has index statistics.  A
// SQLite database that has never been ANALYZEd has no sqlite_stat1 table at all,
// which is the state that makes the stats and bot-hunt pages scan whole covering
// indexes.  MariaDB always reports true: InnoDB maintains its own.
func (d *DB) HasPlannerStats(ctx context.Context) (bool, error) {
	if d.Driver != DriverSQLite {
		return true, nil
	}
	var n int
	err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE name='sqlite_stat1'`).Scan(&n)
	return n > 0, err
}

// EventDateIndexHint returns the driver's hint that pins an unmask_event query
// to the date_created index, or "" when the driver needs none.
//
// RefreshPlannerStats fixes the bad plan for low-cardinality GROUP BY columns
// (the planner can skip-scan them once it has statistics), but NOT for
// ip_address: with roughly one distinct IP per three rows a skip-scan is
// worthless, so even a fully analysed SQLite keeps scanning the whole
// (ip_address, date_created) covering index.  Measured on the tool1-us database
// (3.9M events): `GROUP BY ip_address` over a 1-hour window took 1.4s warm /
// 10.3s cold and did NOT get faster with a narrower window -- pinned to the date
// index it is 0.005s.
//
// Only append this to a query that actually constrains date_created: INDEXED BY
// makes SQLite reject a plan that cannot use the named index.  MariaDB names its
// indexes differently (idx_date) and its optimizer estimates the range from live
// InnoDB statistics, so it is deliberately left unhinted.
func (d *DB) EventDateIndexHint() string {
	if d.Driver == DriverSQLite {
		return " INDEXED BY idx_unmask_event_date"
	}
	return ""
}
