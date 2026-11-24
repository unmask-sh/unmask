package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"time"
)

// The lock a daemon holds while it folds events into the hourly rollup.
//
// The fold (dashboard.AggregateHourly) adds each chunk's counts to the
// stored ones and moves a cursor past the events it has folded.  It reads
// that cursor first, outside the transaction that writes the chunk, so two
// daemons folding at the same moment read the same cursor, fold the same
// events, and add them twice.  Nodes that share one MariaDB -- several nodes
// behind a load balancer -- each run the fold once a minute, so one of them
// at a time must be the one that folds.
//
//   - MariaDB: a named lock (GET_LOCK) on a connection of its own, as a
//     schema update run holds (schema_liveness.go).  The server drops it
//     when that connection goes, so a daemon that dies mid-fold keeps nobody
//     out.  A daemon that finds the lock taken does not wait: the holder is
//     folding the very events it would have folded.
//   - SQLite: nothing to take.  The file has one daemon.
//
// The lock is advisory and lives on its connection: should that connection
// drop while a fold is under way, the server lets the next daemon in before
// this one has finished its chunk.  That window is what is left of the
// double count.
//
// The access log's once-a-minute flush takes a lock of the same kind
// (BeginTrafficFlush), and waits for it: its unique-address sketches are
// read, merged and written back, and two nodes doing that to one minute at
// once kept only the sketch written last.  Its lock rides the connection of
// the flush's own transaction rather than one of its own.

// AggregateLock is the lock for one fold, or for one flush.  Release gives
// it up.
type AggregateLock struct {
	conn    *sql.Conn // MariaDB; nil where there is nothing to hold
	nameSQL string    // the SQL expression that names the lock
}

// aggregateLockNameSQL names the lock after the database, so that two
// installs on one server do not keep each other out.  The server allows 64
// characters.
const aggregateLockNameSQL = "LEFT(CONCAT('unmask_aggregate:', DATABASE()), 64)"

// trafficLockNameSQL names the access-log flush's lock, after the database
// like the fold's.
const trafficLockNameSQL = "LEFT(CONCAT('unmask_traffic:', DATABASE()), 64)"

// trafficLockWaitSeconds: how long a flush waits for another node's.  A flush
// holds the lock for one transaction of upserts.
const trafficLockWaitSeconds = 5

// LockAggregate takes the fold's lock without waiting.  got is false when
// another daemon on this database holds it: the caller skips its fold.  On
// SQLite it always succeeds and holds nothing.
func (d *DB) LockAggregate(ctx context.Context) (lock *AggregateLock, got bool, err error) {
	return d.lockNamed(ctx, aggregateLockNameSQL, 0)
}

// BeginTrafficFlush begins the transaction of the access log's once-a-minute
// flush.  On MariaDB it first takes the flush's lock, waiting up to
// trafficLockWaitSeconds for another node's flush to end -- on the very
// connection the transaction then runs on.  Held on a connection of its own,
// the way the fold holds its lock, it cost the flush two connections, and
// with a pool of two (db.max_conns: 2) the fold's lock and the flush's were
// the whole pool: each waited for a second connection the other held, and
// every query of the daemon waited with them, until the flush's deadline.
//
// got is false when the lock is still another node's by the end of the
// wait: the caller keeps its buckets for the next flush.  done gives the lock
// up and hands the connection back; it is to be called once the transaction
// has been committed or rolled back, and is safe to call when there is
// nothing to give up.  On SQLite there is no lock to take.
func (d *DB) BeginTrafficFlush(ctx context.Context) (tx *sql.Tx, done func(), got bool, err error) {
	nothing := func() {}
	if d == nil {
		return nil, nothing, false, ErrNoDatabase
	}
	if d.Driver != DriverMariaDB {
		tx, err = d.BeginTx(ctx, nil)
		return tx, nothing, err == nil, err
	}
	c, err := d.Conn(ctx)
	if err != nil {
		return nil, nothing, false, err
	}
	var v sql.NullInt64
	if err := c.QueryRowContext(ctx, "SELECT GET_LOCK("+trafficLockNameSQL+", ?)", trafficLockWaitSeconds).Scan(&v); err != nil {
		_ = c.Close()
		return nil, nothing, false, err
	}
	if !v.Valid || v.Int64 != 1 {
		_ = c.Close()
		return nil, nothing, false, nil
	}
	lock := &AggregateLock{conn: c, nameSQL: trafficLockNameSQL}
	tx, err = c.BeginTx(ctx, nil)
	if err != nil {
		lock.Release()
		return nil, nothing, false, err
	}
	return tx, lock.Release, true, nil
}

// lockNamed takes the named lock on a connection of its own, waiting up to
// waitSeconds.
func (d *DB) lockNamed(ctx context.Context, nameSQL string, waitSeconds int) (lock *AggregateLock, got bool, err error) {
	if d == nil || d.Driver != DriverMariaDB {
		return &AggregateLock{}, true, nil
	}
	// The lock sits on a connection of its own for the whole fold, and the
	// fold needs another beside it.  A pool held to a single connection
	// (db.max_conns: 1 under the custom profile) has none to spare -- the
	// fold would wait on its own lock until its budget ran out -- so there
	// the fold runs unlocked, as it always did.
	if d.Stats().MaxOpenConnections == 1 {
		return &AggregateLock{}, true, nil
	}
	c, err := d.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	var v sql.NullInt64
	if err := c.QueryRowContext(ctx, "SELECT GET_LOCK("+nameSQL+", ?)", waitSeconds).Scan(&v); err != nil {
		_ = c.Close()
		return nil, false, err
	}
	if !v.Valid || v.Int64 != 1 {
		_ = c.Close()
		return nil, false, nil
	}
	return &AggregateLock{conn: c, nameSQL: nameSQL}, true, nil
}

// Release gives the lock up.  Safe on a nil lock, on one that holds nothing,
// and more than once.
func (l *AggregateLock) Release() {
	if l == nil || l.conn == nil {
		return
	}
	// Not under the fold's context: that one may be over, and the lock has
	// to go all the same.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var v sql.NullInt64
	err := l.conn.QueryRowContext(ctx, "SELECT RELEASE_LOCK("+l.nameSQL+")").Scan(&v)
	if err != nil || !v.Valid || v.Int64 != 1 {
		// The release did not go through, so the lock may live on in this
		// connection: closed rather than handed back to the pool, where it
		// would turn every later fold away.  The server drops the lock with
		// the connection.
		_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	_ = l.conn.Close()
	l.conn = nil
}
