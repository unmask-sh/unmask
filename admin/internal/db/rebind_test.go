package db

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func rebindTestConn(t *testing.T) *DB {
	t.Helper()
	conn, err := Open(settings.DB{Driver: string(DriverSQLite), SQLitePath: filepath.Join(t.TempDir(), "r.sqlite")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return conn
}

func TestRebindAllowLifetimeCap(t *testing.T) {
	conn := rebindTestConn(t)
	ctx := context.Background()
	now := int64(1_700_000_000)
	for i := 0; i < 3; i++ {
		ok, err := RebindAllow(ctx, conn, "lin-life", "example.com", 3, 100, now+int64(i))
		if err != nil {
			t.Fatalf("allow #%d: %v", i+1, err)
		}
		if !ok {
			t.Fatalf("expected rebind #%d within lifetime cap to pass", i+1)
		}
	}
	ok, err := RebindAllow(ctx, conn, "lin-life", "example.com", 3, 100, now+10)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected rebind #4 past the lifetime cap to be refused")
	}
}

func TestRebindAllowHourlyWindow(t *testing.T) {
	conn := rebindTestConn(t)
	ctx := context.Background()
	now := int64(1_700_000_000)
	for i := 0; i < 2; i++ {
		ok, err := RebindAllow(ctx, conn, "lin-rate", "example.com", 100, 2, now+int64(i))
		if err != nil || !ok {
			t.Fatalf("expected rebind #%d within the hourly window to pass (ok=%v err=%v)", i+1, ok, err)
		}
	}
	if ok, _ := RebindAllow(ctx, conn, "lin-rate", "example.com", 100, 2, now+10); ok {
		t.Fatal("expected rebind #3 in the same window to be refused")
	}
	// The window restarts once it is an hour old; the lifetime budget keeps counting.
	if ok, _ := RebindAllow(ctx, conn, "lin-rate", "example.com", 100, 2, now+3601); !ok {
		t.Fatal("expected the first rebind of a fresh window to pass")
	}
	if ok, _ := RebindAllow(ctx, conn, "lin-rate", "example.com", 100, 2, now+3602); !ok {
		t.Fatal("expected the second rebind of the fresh window to pass")
	}
	if ok, _ := RebindAllow(ctx, conn, "lin-rate", "example.com", 100, 2, now+3603); ok {
		t.Fatal("expected the third rebind of the fresh window to be refused")
	}
}

func TestRebindAllowIndependentLineages(t *testing.T) {
	conn := rebindTestConn(t)
	ctx := context.Background()
	now := int64(1_700_000_000)
	if ok, _ := RebindAllow(ctx, conn, "lin-a", "example.com", 1, 10, now); !ok {
		t.Fatal("lin-a first rebind should pass")
	}
	if ok, _ := RebindAllow(ctx, conn, "lin-a", "example.com", 1, 10, now+1); ok {
		t.Fatal("lin-a second rebind should hit its own cap")
	}
	if ok, _ := RebindAllow(ctx, conn, "lin-b", "example.com", 1, 10, now+2); !ok {
		t.Fatal("lin-b must not be affected by lin-a's spent budget")
	}
}

func TestRebindAllowEmptyLineage(t *testing.T) {
	conn := rebindTestConn(t)
	if ok, err := RebindAllow(context.Background(), conn, "", "example.com", 16, 4, 1); ok || err != nil {
		t.Fatalf("empty lineage must be refused without error (ok=%v err=%v)", ok, err)
	}
}
