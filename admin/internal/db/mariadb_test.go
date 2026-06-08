package db

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func mariadbEnvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

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
	return settings.DB{
		Driver: string(DriverMariaDB),
		MariaDB: settings.MariaDB{
			Host:     host,
			Port:     port,
			User:     mariadbEnvOr("UNMASK_TEST_MARIADB_USER", "root"),
			Password: os.Getenv("UNMASK_TEST_MARIADB_PASSWORD"),
			Database: mariadbEnvOr("UNMASK_TEST_MARIADB_DATABASE", "unmask_test"),
		},
	}
}

// MariaDB is a first-class, wizard-selectable backend (hand-written
// migrations/mariadb/*.sql, ~20 dialect aggregate branches, UTC time_zone
// enforcement) that shipped with ZERO automated coverage -- a MariaDB-only
// fresh-install bug (the argon2id password_hash column width) already escaped
// once.  Docker-gated smoke test: `make test-mariadb` spins up a container and
// sets UNMASK_TEST_MARIADB_HOST; without it the test skips.
func TestMariaDB_MigrateIdempotentAndUTC(t *testing.T) {
	conn, err := Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer conn.Close()
	if conn.Driver != DriverMariaDB {
		t.Fatalf("driver = %q, want mariadb", conn.Driver)
	}

	// Migrate twice: the 2nd run must be a no-op, not an error -- every
	// hand-written MariaDB migration + ALTER must be idempotent.  This is the
	// exact class that broke the fresh install (the password_hash width ALTER).
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate (1st): %v", err)
	}
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate (2nd, idempotency): %v", err)
	}

	// time_zone must be forced to UTC so NOW()/DATE()/DATE_SUB across the
	// aggregate branches match SQLite's UTC-by-default storage.
	var tz string
	if err := conn.QueryRow("SELECT @@session.time_zone").Scan(&tz); err != nil {
		t.Fatalf("read session time_zone: %v", err)
	}
	if tz != "+00:00" {
		t.Errorf("session time_zone = %q, want +00:00", tz)
	}

	// NOW() must evaluate in UTC, not the container's local zone.
	var now time.Time
	if err := conn.QueryRow("SELECT NOW()").Scan(&now); err != nil {
		t.Fatalf("select NOW(): %v", err)
	}
	if d := time.Since(now.UTC()); d < -2*time.Minute || d > 2*time.Minute {
		t.Errorf("NOW() = %v is %v away from UTC now -- time_zone not honored?", now, d)
	}

	// Exercise a migrated table + a date-function aggregate (the dialect path
	// the dashboard's Daily*/Funnel queries depend on).
	var n int
	if err := conn.QueryRow(
		"SELECT COUNT(*) FROM unmask_event WHERE date_created >= DATE_SUB(NOW(), INTERVAL 1 DAY)",
	).Scan(&n); err != nil {
		t.Fatalf("date-function aggregate on unmask_event: %v", err)
	}
}
