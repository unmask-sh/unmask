package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// WALLargeBytes is the write-ahead log size from which the daemon, doctor and
// the retention tab call the file large: four times the journal_size_limit
// the DSN sets (64 MB), which is what a checkpoint that completes leaves
// behind.  Past it, checkpoints are not completing -- a reader holds an older
// snapshot -- and the file only grows (10.7 GB on 2026-09-08).
const WALLargeBytes = 256 << 20

// WALPath is the write-ahead log file next to a SQLite database; "" for
// MariaDB.
func (d *DB) WALPath() string {
	if d.Driver != DriverSQLite || d.SQLitePath == "" {
		return ""
	}
	return d.SQLitePath + "-wal"
}

// WALSize is the size of the write-ahead log file, 0 when there is none.
func (d *DB) WALSize() int64 {
	p := d.WALPath()
	if p == "" {
		return 0
	}
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

// Checkpoint is what one wal_checkpoint reported.
type Checkpoint struct {
	Busy         bool // a reader or writer kept the checkpoint from completing
	LogFrames    int  // frames in the log
	Checkpointed int  // frames copied into the database file; equal to LogFrames when the whole log is in
}

// CheckpointWAL runs a checkpoint of the given mode (PASSIVE, FULL, RESTART or
// TRUNCATE).  wait bounds how long a blocking mode waits for readers and
// writers -- and so how long it holds new writers off; 0 keeps the
// connection's own busy timeout.
func (d *DB) CheckpointWAL(ctx context.Context, mode string, wait time.Duration) (Checkpoint, error) {
	var cp Checkpoint
	if d.Driver != DriverSQLite {
		return cp, errors.New("checkpoint: SQLite only")
	}
	switch mode {
	case "PASSIVE", "FULL", "RESTART", "TRUNCATE":
	default:
		return cp, fmt.Errorf("checkpoint: unknown mode %q", mode)
	}
	conn, err := d.Conn(ctx)
	if err != nil {
		return cp, err
	}
	defer conn.Close()
	if wait > 0 {
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", wait.Milliseconds())); err != nil {
			return cp, err
		}
		// The pool hands this connection out again: put the DSN's timeout back.
		defer func() { _, _ = conn.ExecContext(context.Background(), "PRAGMA busy_timeout=5000") }()
	}
	var busy int
	if err := conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint("+mode+")").Scan(&busy, &cp.LogFrames, &cp.Checkpointed); err != nil {
		return cp, err
	}
	cp.Busy = busy != 0
	return cp, nil
}

// WALTrim is what TrimWAL did.
type WALTrim struct {
	Before, After int64
	Passive       Checkpoint
	Truncated     bool // the TRUNCATE checkpoint went through
	Blocked       bool // the TRUNCATE was tried and a reader still held the log
}

// TrimWAL brings a large write-ahead log back down as far as the readers
// allow: a PASSIVE checkpoint first (copies what it can and blocks nobody),
// then -- only once that covered the whole log -- a TRUNCATE checkpoint with
// a short wait, so a reader still on the log costs new writers a quarter
// second at most rather than the connection's five.  The daemon calls it
// when the log is past WALLargeBytes.
func (d *DB) TrimWAL(ctx context.Context) (WALTrim, error) {
	var t WALTrim
	t.Before = d.WALSize()
	cp, err := d.CheckpointWAL(ctx, "PASSIVE", 0)
	if err != nil {
		return t, err
	}
	t.Passive = cp
	if !cp.Busy && cp.Checkpointed >= cp.LogFrames {
		tc, err := d.CheckpointWAL(ctx, "TRUNCATE", 250*time.Millisecond)
		if err != nil {
			return t, err
		}
		if tc.Busy {
			t.Blocked = true
		} else {
			t.Truncated = true
		}
	}
	t.After = d.WALSize()
	return t, nil
}
