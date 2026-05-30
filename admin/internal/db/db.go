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
			"&_pragma=cache_size(-20000)" + // -20000 = 20MB page cache
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
		cfg.Loc = time.Local
		cfg.Params = map[string]string{"charset": "utf8mb4"}
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
