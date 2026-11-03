package ban

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/safe"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A panic in the loop's write ends that write, not the loop: the file is
// marked to write again, and the next wake after the guard's wait writes
// it.  Through 0.1.53 the loop ended at the first panic, and the expired
// bans stayed in nginx's file for the life of the process.
func TestLoopSurvivesAPanickingFlush(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	panics := make(chan int, 8)
	safe.SetOnPanic(func(name string, n int, _ any) {
		if name == "ban-loop" {
			panics <- n
		}
	})
	t.Cleanup(func() { safe.SetOnPanic(nil) })

	file := filepath.Join(dir, "ban.list")
	mgr := New(d, file, 0)
	good := func(string) string { return "deny" }
	mgr.SetActionResolver(good)
	mgr.Start()
	defer mgr.Close()
	// A row whose action the write resolves through the resolver.
	if err := mgr.AddManualWithScope(context.Background(), "203.0.113.5", "", ScopeIPOnly, "before", "tester", "", 0); err != nil {
		t.Fatal(err)
	}
	mgr.settle()

	// A resolver that panics: the loop's next write dies in it.
	mgr.SetActionResolver(func(string) string { panic("boom") })
	mgr.markDirty()
	mgr.wakeLoop()
	select {
	case n := <-panics:
		if n != 1 {
			t.Errorf("consecutive = %d", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the loop's write did not panic (or the guard did not report it)")
	}
	if !mgr.shouldFlush() {
		t.Error("the file is not marked to write again after the panic")
	}

	// The loop is alive: once the wait is over, its next wake writes the
	// file (the write count is the loop's, not a direct write's).
	mgr.SetActionResolver(good)
	writes := mgr.flushCount()
	time.Sleep(1100 * time.Millisecond) // the wait after one panic
	mgr.markDirty()
	mgr.wakeLoop()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.flushCount() > writes {
			if b, err := os.ReadFile(file); err != nil || !strings.Contains(string(b), "203.0.113.5|") {
				t.Fatalf("the file after the loop's write: %v\n%s", err, b)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the loop did not write the file after the panic")
}
