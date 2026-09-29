package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"syscall"
	"time"
)

// Whether a schema update run is going: the run holds a lock for as long as
// it runs, and the lock goes when its process does.
//
// The record a run writes (MaintSchemaUpdate) cannot say this by itself: a run
// that dies without a word -- killed, out of memory, its host rebooted, its
// container re-created -- leaves it saying "running" for ever, and believing it
// has a price: on SQLite the daemon holds its writes back while a run is going,
// and a second run is refused.  Every way of checking the record against the
// run's process fell short somewhere.  Its id is reused.  Under the daemon's
// unit (ProtectProc=invisible) another user's process, and a `sudo unmask
// migrate` after it has dropped its privileges, cannot be looked at at all.
// A container's host id is new on every re-create, and a run in a sibling
// container has process ids of its own.  A lock needs none of that:
//
//   - SQLite: an flock on a file next to the database.  The kernel drops it
//     when the process ends, however it ends, and it is the same lock from
//     every process and container that opens the same file.
//   - MariaDB: a named lock (GET_LOCK) on the run's own connection, which the
//     server drops when that connection goes -- from any node.
//
// Taking the lock is also what keeps two runs apart: there is no moment
// between checking for another run and recording one's own.

// SchemaRunLock is held by a schema update run for as long as it runs.
type SchemaRunLock struct {
	file *os.File  // SQLite
	conn *sql.Conn // MariaDB
}

// Release gives the lock up.  Safe on a nil lock and more than once.
func (l *SchemaRunLock) Release() {
	if l == nil {
		return
	}
	if l.file != nil {
		_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
		_ = l.file.Close()
		l.file = nil
	}
	if l.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = l.conn.ExecContext(ctx, "DO RELEASE_LOCK("+schemaRunLockNameSQL+")")
		cancel()
		// Closed rather than handed back to the pool: were the release
		// above to fail, the lock would live on in a pooled connection and
		// turn the next run away.  The server drops it with the connection.
		_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = l.conn.Close()
		l.conn = nil
	}
}

// schemaRunLockNameSQL names the MariaDB lock after the database, so that two
// installs on one server do not wait for each other.  The server allows 64
// characters.
const schemaRunLockNameSQL = "LEFT(CONCAT('unmask_schema_update:', DATABASE()), 64)"

// schemaRunLockPath is the SQLite lock file, or "" when there is no database
// file to put it next to.
func (d *DB) schemaRunLockPath() string {
	if d == nil || d.Driver != DriverSQLite || d.SQLitePath == "" {
		return ""
	}
	return d.SQLitePath + ".schema-update.lock"
}

// runLockRetry is how long LockSchemaRun keeps trying for a lock someone else
// has: the daemon's look at the SQLite lock (SchemaRunLockHeld) takes it for
// an instant, and a run that starts in that instant must not read it as
// another run.
const runLockRetry = time.Second

// LockSchemaRun takes the lock a schema update run holds while it runs.  It
// fails with ErrSchemaUpdateRunning when another run has it.
func (d *DB) LockSchemaRun(ctx context.Context) (*SchemaRunLock, error) {
	switch {
	case d.schemaRunLockPath() != "":
		f, err := os.OpenFile(d.schemaRunLockPath(), os.O_RDWR|os.O_CREATE, 0o644)
		if errors.Is(err, os.ErrPermission) {
			// A lock file another user left -- a run as root that kept its
			// privileges (UNMASK_NO_PRIVDROP) -- is locked all the same
			// read-only.  Read-write first: NFS emulates flock with byte-range
			// locks, and an exclusive one there needs a file open for writing.
			f, err = os.Open(d.schemaRunLockPath())
		}
		if err != nil {
			return nil, err
		}
		deadline := time.Now().Add(runLockRetry)
		for {
			err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				return &SchemaRunLock{file: f}, nil
			}
			if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
				_ = f.Close()
				if errors.Is(err, syscall.EWOULDBLOCK) {
					return nil, ErrSchemaUpdateRunning
				}
				return nil, err
			}
			select {
			case <-ctx.Done():
				_ = f.Close()
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	case d != nil && d.Driver == DriverMariaDB:
		c, err := d.Conn(ctx)
		if err != nil {
			return nil, err
		}
		var got sql.NullInt64
		if err := c.QueryRowContext(ctx, "SELECT GET_LOCK("+schemaRunLockNameSQL+", 0)").Scan(&got); err != nil {
			_ = c.Close()
			return nil, err
		}
		if !got.Valid || got.Int64 != 1 {
			_ = c.Close()
			return nil, ErrSchemaUpdateRunning
		}
		return &SchemaRunLock{conn: c}, nil
	}
	return &SchemaRunLock{}, nil // no file to lock (an in-memory database)
}

// SchemaRunLockHeld reports whether a schema update run holds its lock now.
// known is false when that cannot be told: the lock file cannot be opened for
// another reason than not being there, or the server does not answer.
func (d *DB) SchemaRunLockHeld(ctx context.Context) (held, known bool) {
	switch {
	case d.schemaRunLockPath() != "":
		f, err := os.Open(d.schemaRunLockPath())
		if errors.Is(err, os.ErrNotExist) {
			return false, true // no run has ever been here
		}
		if err != nil {
			return false, false
		}
		defer f.Close()
		// A shared lock, given straight back: it conflicts with a run's
		// exclusive one, and with no other look like this one.
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return true, true
		}
		if err != nil {
			return false, false
		}
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return false, true
	case d != nil && d.Driver == DriverMariaDB:
		var holder sql.NullInt64
		if err := d.QueryRowContext(ctx, "SELECT IS_USED_LOCK("+schemaRunLockNameSQL+")").Scan(&holder); err != nil {
			return false, false
		}
		return holder.Valid, true
	}
	return false, false
}

// SchemaUpdateAlive reports whether the run rec describes is still going: it
// says it is, and its lock is held.
func (d *DB) SchemaUpdateAlive(ctx context.Context, rec SchemaUpdateRecord, now time.Time) bool {
	if rec.State != SchemaUpdateRunning {
		return false
	}
	if held, known := d.SchemaRunLockHeld(ctx); known {
		return held
	}
	// The lock cannot be looked at: believe the record while it is young.
	limit := 3 * time.Duration(rec.EstHighSec) * time.Second
	if limit < time.Hour {
		limit = time.Hour
	}
	return now.Sub(time.Unix(rec.StartedAt, 0)) < limit
}
