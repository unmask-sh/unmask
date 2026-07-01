// migrator: numbered embedded migration runner.
//
// Design (= minimal version inspired by zabbix / cacti / golang-migrate):
//
//  1. Numbered SQL files like `0001_xxx.sql` / `0002_xxx.sql` ... live in
//     per-driver dirs (= migrations/sqlite/ / migrations/mariadb/).
//  2. At startup (= via Migrate()), create the schema_migrations table and
//     read the applied versions.
//  3. Existing v0.1 DBs were already legacy-normalized by ensure*, so if
//     schema_migrations is empty AND unmask_event exists, INSERT version=1
//     as the baseline (= run nothing).
//  4. Apply pending SQL by ascending version.  Stop on failure (= don't
//     proceed to subsequent migrations).
//  5. Forward-only.  Downgrade is handled via backup → restore.
//
// Operating procedure when a feature requires a schema change:
//
//	Just add migrations/sqlite/0002_xxx.sql + migrations/mariadb/0002_xxx.sql.
//	Use the same version number on both drivers (= prevents version drift).
package db

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/sqlite/*.sql migrations/mariadb/*.sql
var migrationFS embed.FS

// migrationFileRE: extract the version number from the filename.  Fixed 4 digits (= 0001 to 9999).
var migrationFileRE = regexp.MustCompile(`^(\d{4})_.*\.sql$`)

// RunMigrations: apply pending SQL migrations in order.  Idempotent.
//
// Intended to be called after Migrate() (= the legacy ensure* path).  Order:
//
//	Migrate()
//	├─ ensure* (= v0 → v1 normalize, idempotent ALTER family)
//	├─ schema SQL (= CREATE TABLE IF NOT EXISTS)
//	├─ ApplyCookieMinuteMigrationData
//	└─ RunMigrations()                     ← new framework.  v1 baseline + v2+ deltas
func RunMigrations(conn *DB) error {
	if err := ensureSchemaMigrationsTable(conn); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}
	if err := markBaselineIfNeeded(conn); err != nil {
		return fmt.Errorf("mark baseline: %w", err)
	}
	current, err := currentMigrationVersion(conn)
	if err != nil {
		return fmt.Errorf("read current version: %w", err)
	}
	pending, err := listPendingMigrations(string(conn.Driver), current)
	if err != nil {
		return fmt.Errorf("list pending: %w", err)
	}
	for _, m := range pending {
		body, err := migrationFS.ReadFile(m.path)
		if err != nil {
			return fmt.Errorf("read %s: %w", m.path, err)
		}
		for _, stmt := range splitStatements(string(body)) {
			s := strings.TrimSpace(stmt)
			if s == "" {
				continue
			}
			if _, err := conn.Exec(s); err != nil {
				return fmt.Errorf("apply %s: %w\n--- stmt ---\n%s", m.name, err, s)
			}
		}
		if _, err := conn.Exec("INSERT INTO schema_migrations (version, name) VALUES (?, ?)", m.version, m.name); err != nil {
			return fmt.Errorf("record %s: %w", m.name, err)
		}
	}
	return nil
}

// ensureSchemaMigrationsTable: create the version-history table (= CREATE TABLE IF NOT EXISTS).
func ensureSchemaMigrationsTable(conn *DB) error {
	var stmt string
	if conn.Driver == DriverMariaDB {
		stmt = `CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INT NOT NULL COMMENT 'numbered migration version applied',
            name       VARCHAR(128) NOT NULL COMMENT 'migration file name (e.g. 0006_aggregate_hourly)',
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'when this migration was applied (UTC)',
            PRIMARY KEY (version)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Applied-migration version history for the numbered migration framework'`
	} else {
		stmt = `CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,                                  -- numbered migration version applied
            name       TEXT NOT NULL,                                        -- migration file name (e.g. 0006_aggregate_hourly)
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP           -- when this migration was applied (UTC)
        )`
	}
	_, err := conn.Exec(stmt)
	return err
}

// markBaselineIfNeeded: mark an existing v0.1 DB as having v1 applied.
//
// If schema_migrations is empty AND the unmask_event table exists → INSERT version=1.
// (= assumes we're right after ensure* + schema SQL ran the v1 baseline)
//
// On a fresh install (= no unmask_event), do nothing.  The v1 baseline.sql
// does not exist as a migration file, so until a new migration is added,
// nothing else runs either.
func markBaselineIfNeeded(conn *DB) error {
	var n int
	if err := conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	has, err := hasTable(conn, "unmask_event")
	if err != nil {
		return err
	}
	if !has {
		return nil
	}
	_, err = conn.Exec("INSERT INTO schema_migrations (version, name) VALUES (?, ?)", 1, "0001_baseline")
	return err
}

// currentMigrationVersion: max applied version.  Return 0 if the history is empty.
func currentMigrationVersion(conn *DB) (int, error) {
	var v sql.NullInt64
	if err := conn.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

// migrationEntry: one detected migration file.
type migrationEntry struct {
	version int
	name    string
	path    string
}

// listPendingMigrations: return pending migrations from the driver's embed FS, in ascending version order.
func listPendingMigrations(driver string, current int) ([]migrationEntry, error) {
	dir := "migrations/" + driver
	entries, err := fs.ReadDir(migrationFS, dir)
	if err != nil {
		// If the per-driver dir does not exist, no-op (= don't throw).  Also
		// covers the fresh-install case where no migration files have been
		// placed yet.
		return nil, nil
	}
	var migs []migrationEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationFileRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, _ := strconv.Atoi(m[1])
		if v <= current {
			continue
		}
		migs = append(migs, migrationEntry{
			version: v,
			name:    strings.TrimSuffix(e.Name(), ".sql"),
			path:    dir + "/" + e.Name(),
		})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	return migs, nil
}
