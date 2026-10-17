package db

import (
	"context"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"testing"
	"time"

	msqlite "modernc.org/sqlite"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestRowsStayUnderTheContextsWatch: a query that streams its rows is cut
// short at the context's deadline like one that works in a single step --
// the library watches the first step only (see sqlite_ctx.go).  A row here
// costs a few milliseconds through a function registered for the test; two
// thousand of them would take ten seconds, the deadline is a fraction of one.
func TestRowsStayUnderTheContextsWatch(t *testing.T) {
	msqlite.MustRegisterDeterministicScalarFunction("unmask_test_slow", 1, func(_ *msqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		time.Sleep(5 * time.Millisecond)
		return args[0], nil
	})
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "w.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		if _, err := tx.Exec(`INSERT INTO t (id) VALUES (?)`, i); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Without a deadline every row comes.
	n := 0
	rows, err := d.QueryContext(context.Background(), `SELECT unmask_test_slow(id) FROM t WHERE id < 20`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		n++
	}
	rows.Close()
	if n != 20 {
		t.Fatalf("%d rows without a deadline, want 20", n)
	}

	// With one, the rows stop soon after it.  The first rows come at once
	// (the first step is the library's own watched one), and the fifth row's
	// step runs a ten-second subquery: the step nothing but this package's
	// watch reaches -- database/sql's close waits for the step to end.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	rows, err = d.QueryContext(ctx, `SELECT a.id FROM t a WHERE a.id < 4 OR (SELECT COUNT(*) FROM t b WHERE unmask_test_slow(b.id) >= 0) > 1990`)
	if err != nil {
		t.Fatal(err)
	}
	n = 0
	for rows.Next() {
		n++
	}
	err = rows.Err()
	rows.Close()
	took := time.Since(t0)
	if took > 3*time.Second {
		t.Fatalf("the rows ran %v past a 300 ms deadline (%d rows): the watch does not reach past the first step", took, n)
	}
	if err == nil || !(errors.Is(err, context.DeadlineExceeded) || isInterrupted(err)) {
		t.Errorf("rows ended with %v after %d rows, want the deadline or an interrupt", err, n)
	}
	if n >= 5 {
		t.Errorf("%d rows came although the deadline passed in the fifth row's step", n)
	}

	// The connection goes on serving after the interrupt.
	var c int
	if err := d.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM t`).Scan(&c); err != nil || c != 2000 {
		t.Errorf("after the interrupt: count %d, %v", c, err)
	}
}

// isInterrupted: the library's error for a statement cut short.
func isInterrupted(err error) bool {
	var e *msqlite.Error
	return errors.As(err, &e) && e.Code() == 9 // SQLITE_INTERRUPT
}
