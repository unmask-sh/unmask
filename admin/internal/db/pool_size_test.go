package db

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestMaxOpenForDriver: the MariaDB pool is sized for a server, not for
// this process's CPUs as the SQLite pool is, and the operator's custom
// db.max_conns bounds either.
func TestMaxOpenForDriver(t *testing.T) {
	if got := maxOpenFor(DriverMariaDB, settings.DB{}); got != mariadbMaxOpen {
		t.Fatalf("mariadb default pool = %d, want %d", got, mariadbMaxOpen)
	}
	custom := settings.DB{PerfProfile: settings.PerfProfileCustom, MaxConns: 40}
	if got := maxOpenFor(DriverMariaDB, custom); got != 40 {
		t.Fatalf("mariadb custom pool = %d, want 40", got)
	}
	custom.MaxConns = 1000
	if got := maxOpenFor(DriverMariaDB, custom); got != mariadbMaxOpenCustomCeil {
		t.Fatalf("mariadb custom pool past the ceiling = %d, want %d", got, mariadbMaxOpenCustomCeil)
	}
	if got, want := maxOpenFor(DriverSQLite, settings.DB{}), sqliteMaxOpenFor(settings.DB{}); got != want {
		t.Fatalf("sqlite pool = %d, want the CPU-derived %d", got, want)
	}
	if got := maxOpenFor(DriverSQLite, custom); got != sqliteMaxConnsCustomCeil {
		t.Fatalf("sqlite custom pool past the ceiling = %d, want %d", got, sqliteMaxConnsCustomCeil)
	}
}
