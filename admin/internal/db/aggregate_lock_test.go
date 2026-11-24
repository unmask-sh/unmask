package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

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

// On SQLite the flush's transaction is an ordinary one: there is no lock to
// take, and nothing to give up afterwards.
func TestBeginTrafficFlushOnSQLiteIsAPlainTransaction(t *testing.T) {
	d, err := Open(settings.DB{Driver: string(DriverSQLite), SQLitePath: filepath.Join(t.TempDir(), "f.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	tx, done, got, err := d.BeginTrafficFlush(ctx)
	if err != nil || !got || tx == nil {
		t.Fatalf("got=%v err=%v tx=%v", got, err, tx)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE t (a INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	done()
	done()
	var nodb *DB
	if _, done, got, err := nodb.BeginTrafficFlush(ctx); err == nil || got {
		t.Errorf("no database: got=%v err=%v, want an error", got, err)
	} else {
		done()
	}
}

// TestMariaDB_TrafficFlushWaitsForTheOther: the access-log flush's lock is
// one daemon's at a time, and a second flush waits for it instead of turning
// away -- it begins once the first has ended.  It is a lock of its own: the
// fold's lock held meanwhile keeps nobody's flush out.
func TestMariaDB_TrafficFlushWaitsForTheOther(t *testing.T) {
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

	fold, got, err := one.LockAggregate(ctx)
	if err != nil || !got {
		t.Fatalf("the fold's lock: got=%v err=%v", got, err)
	}
	defer fold.Release()
	first, firstDone, got, err := one.BeginTrafficFlush(ctx)
	if err != nil || !got {
		t.Fatalf("the first flush, with the fold's lock held: got=%v err=%v", got, err)
	}
	done := make(chan bool, 1)
	start := time.Now()
	go func() {
		tx, d, got, err := two.BeginTrafficFlush(ctx)
		if err == nil && got {
			_ = tx.Rollback()
			d()
		}
		done <- err == nil && got
	}()
	select {
	case <-done:
		t.Fatal("the second flush began while the first held the lock")
	case <-time.After(500 * time.Millisecond):
	}
	if err := first.Commit(); err != nil {
		t.Fatalf("the first flush's commit: %v", err)
	}
	firstDone()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("the second flush did not begin once the first had ended")
		}
		if waited := time.Since(start); waited >= trafficLockWaitSeconds*time.Second {
			t.Errorf("the second flush waited %v, as long as its whole wait", waited)
		}
	case <-time.After(trafficLockWaitSeconds * time.Second):
		t.Fatal("the second flush was still waiting after the first had ended")
	}
}

// TestMariaDB_TrafficFlushNeedsOneConnection: with a pool of two, a flush
// begins and commits while the fold holds its lock.  The fold's lock sits on
// a connection of its own; when the flush's lock did too, the two locks were
// the whole pool, the flush's transaction and the fold's next statement each
// waited for a connection the other held, and every other query of the daemon
// waited with them until the flush's deadline.
func TestMariaDB_TrafficFlushNeedsOneConnection(t *testing.T) {
	cfg := mariadbSettingsFromEnv(t)
	d, err := Open(cfg)
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer d.Close()
	d.SetMaxOpenConns(2)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	fold, got, err := d.LockAggregate(ctx)
	if err != nil || !got {
		t.Fatalf("the fold's lock: got=%v err=%v", got, err)
	}
	defer fold.Release()
	tx, done, got, err := d.BeginTrafficFlush(ctx)
	if err != nil || !got {
		t.Fatalf("the flush, with the fold's lock on the pool's other connection: got=%v err=%v", got, err)
	}
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatalf("a statement of the flush's transaction: %d, %v", one, err)
	}
	if in := d.Stats().InUse; in != 2 {
		t.Errorf("%d connections in use with the fold's lock and a flush under way, want 2", in)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("the flush's commit: %v", err)
	}
	done()
	// The connection is back, and without the lock: the fold's next
	// statement has one to run on, and another flush begins at once.
	if err := d.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatalf("a query once the flush is done: %v", err)
	}
	tx, done, got, err = d.BeginTrafficFlush(ctx)
	if err != nil || !got {
		t.Fatalf("the next flush: got=%v err=%v", got, err)
	}
	_ = tx.Rollback()
	done()
}
