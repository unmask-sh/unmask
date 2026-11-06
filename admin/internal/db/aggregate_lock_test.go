package db

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// SQLite has one daemon to a file, so the fold's lock holds nothing there:
// it is always given, to any number of callers, and releasing it does
// nothing -- on a nil lock and a second time as well.
func TestLockAggregateOnSQLiteHoldsNothing(t *testing.T) {
	d, err := Open(settings.DB{Driver: string(DriverSQLite), SQLitePath: filepath.Join(t.TempDir(), "l.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	a, got, err := d.LockAggregate(ctx)
	if err != nil || !got {
		t.Fatalf("first lock: got=%v err=%v", got, err)
	}
	b, got, err := d.LockAggregate(ctx)
	if err != nil || !got {
		t.Fatalf("second lock while the first is held: got=%v err=%v", got, err)
	}
	a.Release()
	a.Release()
	b.Release()
	var none *AggregateLock
	none.Release()
	// And on no database at all (a caller that has none passes nil).
	var nodb *DB
	if l, got, err := nodb.LockAggregate(ctx); err != nil || !got {
		t.Errorf("no database: got=%v err=%v", got, err)
	} else {
		l.Release()
	}
}

// TestMariaDB_AggregateLockIsExclusive: on MariaDB the lock is one daemon's
// at a time -- a second taker is told so without waiting -- it is free again
// after Release, and the connection that held it goes back to the pool
// without it.  Two handles stand for two daemons on one database.
func TestMariaDB_AggregateLockIsExclusive(t *testing.T) {
	cfg := mariadbSettingsFromEnv(t)
	one, err := Open(cfg)
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer one.Close()
	two, err := Open(cfg)
	if err != nil {
		t.Fatalf("open mariadb (second daemon): %v", err)
	}
	defer two.Close()
	ctx := context.Background()

	held, got, err := one.LockAggregate(ctx)
	if err != nil || !got {
		t.Fatalf("the first daemon's lock: got=%v err=%v", got, err)
	}
	if l, got, err := two.LockAggregate(ctx); err != nil || got {
		l.Release()
		t.Fatalf("the second daemon took the lock while the first held it (got=%v err=%v)", got, err)
	}
	// Nor a second fold in the first daemon itself, on another connection.
	if l, got, err := one.LockAggregate(ctx); err != nil || got {
		l.Release()
		t.Fatalf("a second connection of the same daemon took the lock (got=%v err=%v)", got, err)
	}
	held.Release()
	held.Release() // twice is harmless

	again, got, err := two.LockAggregate(ctx)
	if err != nil || !got {
		t.Fatalf("after the release the second daemon still cannot take it: got=%v err=%v", got, err)
	}
	again.Release()
	// The released connections hold nothing: every connection of the first
	// daemon's pool can take the lock in turn.
	for i := 0; i < 5; i++ {
		l, got, err := one.LockAggregate(ctx)
		if err != nil || !got {
			t.Fatalf("round %d: a released lock lives on in a pooled connection (got=%v err=%v)", i, got, err)
		}
		l.Release()
	}
}
