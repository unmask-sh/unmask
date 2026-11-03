package safe

import (
	"sync"
	"testing"
	"time"
)

// A guard recovers an iteration's panic and the loop goes on: the count of
// consecutive panics grows, the wait before the next try doubles, the hook
// is told each one, and an iteration that returns resets both.
func TestGuardRecoversAndBacksOff(t *testing.T) {
	var mu sync.Mutex
	var told []int
	SetOnPanic(func(name string, n int, v any) {
		mu.Lock()
		defer mu.Unlock()
		if name != "test-loop" || v != "boom" {
			t.Errorf("hook got %q %v", name, v)
		}
		told = append(told, n)
	})
	t.Cleanup(func() { SetOnPanic(nil) })

	g := NewGuard("test-loop")
	if !g.Ready() {
		t.Fatal("a fresh guard is not ready")
	}
	for i := 1; i <= 3; i++ {
		if !g.Run(func() { panic("boom") }) {
			t.Fatalf("panic %d not reported", i)
		}
		if g.Consecutive() != i {
			t.Errorf("after panic %d: consecutive = %d", i, g.Consecutive())
		}
		if g.Ready() {
			t.Errorf("after panic %d: ready at once", i)
		}
	}
	mu.Lock()
	if len(told) != 3 || told[0] != 1 || told[2] != 3 {
		t.Errorf("hook told %v", told)
	}
	mu.Unlock()

	// An iteration that returns resets the count and the wait, whatever
	// came before.
	g.mu.Lock()
	g.notBefore = time.Now().Add(-time.Second)
	g.mu.Unlock()
	if !g.Ready() {
		t.Error("not ready once the wait is over")
	}
	if g.Run(func() {}) {
		t.Error("a quiet iteration reported a panic")
	}
	if g.Consecutive() != 0 || !g.Ready() {
		t.Errorf("after a quiet iteration: consecutive %d, ready %v", g.Consecutive(), g.Ready())
	}

	for n, want := range map[int]time.Duration{0: 0, 1: time.Second, 2: 2 * time.Second, 5: 16 * time.Second, 9: 256 * time.Second, 10: backoffMax, 100: backoffMax} {
		if got := backoffFor(n); got != want {
			t.Errorf("backoffFor(%d) = %s, want %s", n, got, want)
		}
	}
}

// Without a hook a panic is still recovered.
func TestGuardWithoutAHook(t *testing.T) {
	SetOnPanic(nil)
	g := NewGuard("quiet")
	if !g.Run(func() { panic("boom") }) || g.Consecutive() != 1 {
		t.Error("the panic was not recovered and counted")
	}
}
