package db

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A query's context deadline has to stop the query, not only the wait for its
// answer.  The admin gives every read a budget and renders what came back in
// time, and that only holds if the deadline interrupts SQLite.  The driver this
// replaced noticed it once SQLite handed back a row, and an aggregate does all
// of its work before its first row: a count ran to the end whatever the
// deadline, the page waited for it, and the pooled connection stayed taken
// (2026-10-14: on a database larger than memory, a dashboard whose reads had
// 5 s each did not answer for minutes).
func TestQueryDeadlineInterruptsTheQuery(t *testing.T) {
	d, err := Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "q.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	// Sixty million steps, all before the first row: half a minute or more of
	// work, so a deadline that does not interrupt shows plainly.
	const count = `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 60000000) SELECT COUNT(*) FROM c`
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	var n int64
	err = d.QueryRowContext(ctx, count).Scan(&n)
	took := time.Since(start)
	if err == nil {
		t.Fatalf("the count finished (%d) despite a 200ms deadline", n)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the context's deadline", err)
	}
	if took > 3*time.Second {
		t.Fatalf("the query came back %v after a 200ms deadline: the deadline did not interrupt it", took.Round(time.Millisecond))
	}

	// The connection it ran on is usable at once: the interrupt ended that
	// statement only.
	if err := d.QueryRowContext(context.Background(), `SELECT 1`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("a query after the interrupted one: n=%d err=%v", n, err)
	}
}
