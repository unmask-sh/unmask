// Package db: thin SQLite / MariaDB abstraction.
//
// ORM 不採用. 集計クエリは生 SQL の方が明快なので database/sql のごく薄い
// ラッパーだけを提供する.
//
// driver 差分:
//   - placeholder: SQLite は ?, MariaDB は %s ではなく ? も使えるが MySQL 接続では ?
//     どちらも ? で揃える (database/sql 標準).
//   - 「N 分前」 SQL fragment は driver で違うので NowMinusMinutes() で生成.
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

	"github.com/shoeisha/unmask/admin/internal/settings"
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
// missing (一発で立ち上がる体験のため).
func Open(s settings.DB) (*DB, error) {
	switch s.Driver {
	case "", string(DriverSQLite):
		if err := os.MkdirAll(filepath.Dir(s.SQLitePath), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir sqlite parent: %w", err)
		}
		// _pragma=... で WAL + busy timeout. challenge write と dashboard read の競合用.
		dsn := s.SQLitePath +
			"?_pragma=journal_mode(WAL)" +
			"&_pragma=synchronous(NORMAL)" +
			"&_pragma=busy_timeout(3000)"
		conn, err := sql.Open("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		// SQLite 単一書込み制約: write は逐次. read は別 goroutine で並列でいい.
		conn.SetMaxOpenConns(1)
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
// the active driver.  Use it inline (= clientside parameterization は不可).
func (d *DB) NowMinusMinutes(n int) string {
	if d.Driver == DriverSQLite {
		return fmt.Sprintf("datetime('now', '-%d minutes')", n)
	}
	return fmt.Sprintf("DATE_SUB(NOW(), INTERVAL %d MINUTE)", n)
}
