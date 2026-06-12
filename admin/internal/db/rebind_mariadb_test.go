package db

import (
	"context"
	"testing"
)

// The rebind cap is one conditional UPDATE with CASE arithmetic plus an
// upsert, written once with shared SQL and a per-dialect INSERT branch --
// exactly the raw-SQL class the sqlite unit tests can't vouch for on MariaDB
// (ON DUPLICATE KEY vs ON CONFLICT, backtick-quoted `count`).  Docker-gated
// like the other TestMariaDB_* smoke tests: `make test-mariadb` runs it,
// without UNMASK_TEST_MARIADB_HOST it skips.
func TestMariaDB_RebindAllow(t *testing.T) {
	conn, err := Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer conn.Close()
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx,
		"DELETE FROM unmask_rebind_lineage WHERE lineage LIKE 'mdbt-%'"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	now := int64(1_700_000_000)
	// Lifetime cap of 2: two pass, the third is refused.
	for i := 0; i < 2; i++ {
		ok, err := RebindAllow(ctx, conn, "mdbt-life", "example.com", 2, 10, now+int64(i))
		if err != nil || !ok {
			t.Fatalf("rebind #%d should pass (ok=%v err=%v)", i+1, ok, err)
		}
	}
	if ok, err := RebindAllow(ctx, conn, "mdbt-life", "example.com", 2, 10, now+5); ok || err != nil {
		t.Fatalf("rebind #3 past the lifetime cap should be refused (ok=%v err=%v)", ok, err)
	}

	// Hourly window of 1: one passes, the next in-window is refused, a fresh
	// window an hour later passes again (CASE branch on both drivers).
	if ok, _ := RebindAllow(ctx, conn, "mdbt-rate", "example.com", 10, 1, now); !ok {
		t.Fatal("first windowed rebind should pass")
	}
	if ok, _ := RebindAllow(ctx, conn, "mdbt-rate", "example.com", 10, 1, now+30); ok {
		t.Fatal("second rebind in the same window should be refused")
	}
	if ok, _ := RebindAllow(ctx, conn, "mdbt-rate", "example.com", 10, 1, now+3601); !ok {
		t.Fatal("first rebind of the next window should pass")
	}
}
