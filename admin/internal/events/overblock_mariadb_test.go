package events

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

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

// TestMariaDB_OverBlockStats runs the breaker's signal query against a real
// MariaDB.  The browser-grade filter leans on `NOT LIKE ... ESCAPE '|'` and
// COALESCE over nullable columns -- constructs this repo uses nowhere else,
// and believed-portable SQL is exactly the class the dialect split has burned
// before.  Same seed and expectations as the SQLite TestOverBlockStats.
func TestMariaDB_OverBlockStats(t *testing.T) {
	d, err := db.Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	// The container DB is shared across the TestMariaDB_* suite; start clean.
	if _, err := d.ExecContext(ctx, "DELETE FROM unmask_event"); err != nil {
		t.Fatalf("clear unmask_event: %v", err)
	}

	now := time.Now().UTC()
	ins := func(ip, phase, ua, verdict string, n int) {
		for i := 0; i < n; i++ {
			ev := &Event{IPPacked: PackIP(ip), Phase: phase, UserAgent: ua, JA4Verdict: verdict, OccurredAt: now}
			if err := Insert(ctx, d, ev); err != nil {
				t.Fatal(err)
			}
		}
	}
	const chrome = "Mozilla/5.0 Chrome/126"
	ins("10.0.0.1", "serve", chrome, "", 5)
	ins("10.0.0.2", "serve", chrome, "suspect_chrome_h1", 3)
	ins("10.0.0.3", "serve", chrome, "ok", 1)
	ins("10.0.0.4", "load", chrome, "", 4)
	ins("10.0.0.5", "serve", "", "", 7)               // no User-Agent -> bot-class
	ins("10.0.0.6", "serve", "curl/8", "bot_curl", 6) // confirmed-bot verdict -> bot-class

	serves, ips, loads, err := OverBlockStats(ctx, d, 60)
	if err != nil {
		t.Fatal(err)
	}
	if loads != 4 {
		t.Errorf("loads = %d, want 4", loads)
	}
	if serves != 9 {
		t.Errorf("serves = %d, want 9 (load events and bot-class serves must be excluded)", serves)
	}
	if ips != 3 {
		t.Errorf("distinct IPs = %d, want 3 (bot-class IPs must be excluded)", ips)
	}
}
