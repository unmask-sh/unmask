// Package db: thin SQLite / MariaDB abstraction.
//
// No ORM.  Aggregation queries read more clearly as raw SQL, so this package
// only exposes a very thin wrapper around database/sql.
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

	mysql "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

type Driver string

const (
	DriverSQLite  Driver = "sqlite"
	DriverMariaDB Driver = "mariadb"
)

type DB struct {
	*sql.DB
	Driver Driver
}

// Open returns a configured *DB. SQLite path's parent directory is created if
// missing (so first-run "just works").
func Open(s settings.DB) (*DB, error) {
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
		conn, err := sql.Open("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		// WAL mode allows multiple parallel readers; writes are serial (SQLite constraint).
		// MaxOpen=1 also serializes reads, so the dashboard contends with auth_request
		// writes and hits the 8s timeout.  Parallelising reads improves latency.
		conn.SetMaxOpenConns(8)
		conn.SetMaxIdleConns(4)
		conn.SetConnMaxLifetime(time.Hour)
		if err := conn.PingContext(context.Background()); err != nil {
			conn.Close()
			return nil, err
		}
		return &DB{DB: conn, Driver: DriverSQLite}, nil

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
		conn, err := sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			return nil, err
		}
		conn.SetMaxOpenConns(8)
		conn.SetMaxIdleConns(2)
		conn.SetConnMaxLifetime(30 * time.Minute)
		if err := conn.PingContext(context.Background()); err != nil {
			conn.Close()
			return nil, err
		}
		return &DB{DB: conn, Driver: DriverMariaDB}, nil

	default:
		return nil, errors.New("unknown db driver: " + s.Driver)
	}
}

// NowMinusMinutes returns a SQL fragment representing "now - n minutes" for
// the active driver.  Use it inline (= cannot be parameterised client-side).
func (d *DB) NowMinusMinutes(n int) string {
	if d.Driver == DriverSQLite {
		return fmt.Sprintf("datetime('now', '-%d minutes')", n)
	}
	return fmt.Sprintf("DATE_SUB(NOW(), INTERVAL %d MINUTE)", n)
}
