package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Consuming a rebind is a write, and the visitor is waiting on the request
// that asks for it.  Against a schema update's write lock it would wait out
// the busy timeout and then fail; it is refused at once instead, and the
// visitor meets the challenge they would have met without a rebind.
func TestRebindRefusedAtOnceWhileWritesAreHeld(t *testing.T) {
	conn := migratedDB(t)
	conn.HoldWrites(true)
	t0 := time.Now()
	ok, err := RebindAllow(context.Background(), conn, "lineage-1", "host", 5, 5, time.Now().Unix())
	if ok || !errors.Is(err, ErrWritesHeld) {
		t.Fatalf("RebindAllow = (%v, %v), want refused with ErrWritesHeld", ok, err)
	}
	if took := time.Since(t0); took > 200*time.Millisecond {
		t.Errorf("the refusal took %v; it must not wait for the lock", took)
	}
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM unmask_rebind_lineage`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("a refused rebind left %d row(s)", n)
	}
	conn.HoldWrites(false)
	if ok, err := RebindAllow(context.Background(), conn, "lineage-1", "host", 5, 5, time.Now().Unix()); err != nil || !ok {
		t.Fatalf("after the hold: RebindAllow = (%v, %v)", ok, err)
	}
}
