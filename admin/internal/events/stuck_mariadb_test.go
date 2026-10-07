package events

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// mariadbSettingsFromEnv mirrors internal/db's docker-gated helper (that one
// is package-private, and events -> db is already an import edge, so it
// cannot be shared from here).  Skips unless `make test-mariadb` set the env.
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

// TestMariaDB_StuckVisitors runs the breaker's reading against a real
// MariaDB: the phase lists, the IN list of passing addresses and the
// date_created that arrives as a time there, not as text.  Same seed and
// expectations as the SQLite TestStuckVisitors.
func TestMariaDB_StuckVisitors(t *testing.T) {
	d, err := db.Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// The container DB is shared across the TestMariaDB_* suite; start clean.
	if _, err := d.ExecContext(context.Background(), "DELETE FROM unmask_event"); err != nil {
		t.Fatalf("clear unmask_event: %v", err)
	}
	seedStuck(t, d)
	checkStuck(t, d)
}
