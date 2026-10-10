package events

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// OnInsert sees every event exactly once, on whichever entry point it took,
// and before the row is written.
func TestOnInsertSeesEachEventOnce(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/e.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	var seen []string
	OnInsert = func(e *Event) { seen = append(seen, e.Phase) }
	t.Cleanup(func() { OnInsert = nil })

	ctx := context.Background()
	if err := Insert(ctx, d, &Event{IPPacked: PackIP("1.2.3.4"), Phase: "serve"}); err != nil {
		t.Fatal(err)
	}
	InsertAsync(d, &Event{IPPacked: PackIP("1.2.3.5"), Phase: "load"})
	// The async row lands from a goroutine (no flusher runs in this test, or
	// the package's one takes it); either way the notice was already given.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		_ = d.QueryRowContext(ctx, "SELECT COUNT(*) FROM unmask_event").Scan(&n)
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(seen) != 2 || seen[0] != "serve" || seen[1] != "load" {
		t.Errorf("OnInsert saw %v, want [serve load]", seen)
	}
	// An invalid event is refused before the hook: nothing to count.
	seen = nil
	if err := Insert(ctx, d, nil); err == nil {
		t.Error("nil event inserted")
	}
	if len(seen) != 0 {
		t.Errorf("hook saw an invalid event: %v", seen)
	}
}
