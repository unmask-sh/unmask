package safe

import (
	"log"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// A Guard recovers the panics of one loop's iterations and keeps count of
// the consecutive ones, so the loop goes on after a panic -- the events
// flusher, the ban loop and the access-log flush each recovered the loop as
// a whole through 0.1.53, and one panic ended them for the life of the
// process, with the daemon healthy to every probe -- and so that a panic
// that comes back every time is not retried every tick: each one in a row
// doubles the wait before the next try (backoffFor), and OnPanic is told
// the count, for the notice that says the loop is stuck.
type Guard struct {
	name string
	mu   sync.Mutex
	// consecutive: panics since the last iteration that returned.
	consecutive int
	// notBefore: when the next iteration may run; zero after a success.
	notBefore time.Time
}

// NewGuard returns a guard for the loop called name (the log's and the
// notice's word for it).
func NewGuard(name string) *Guard { return &Guard{name: name} }

// Run runs one iteration with recovery and reports whether it panicked.  A
// panic is logged with its stack, counted, and told to OnPanic; an
// iteration that returns resets the count and the wait.
func (g *Guard) Run(fn func()) (panicked bool) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		panicked = true
		g.mu.Lock()
		g.consecutive++
		n := g.consecutive
		wait := backoffFor(n)
		g.notBefore = time.Now().Add(wait)
		g.mu.Unlock()
		log.Printf("PANIC recovered in %s (%d in a row; next try in %s): %v\n%s", g.name, n, wait, r, debug.Stack())
		if hook := onPanic.Load(); hook != nil {
			(*hook)(g.name, n, r)
		}
	}()
	fn()
	g.mu.Lock()
	g.consecutive = 0
	g.notBefore = time.Time{}
	g.mu.Unlock()
	return false
}

// Ready reports whether the loop may run an iteration now: true when the
// last one returned, or the wait after the last panic is over.
func (g *Guard) Ready() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.notBefore.IsZero() || !time.Now().Before(g.notBefore)
}

// Consecutive is how many iterations in a row have panicked.
func (g *Guard) Consecutive() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.consecutive
}

// backoffMax caps the wait between tries of a loop that panics every time.
const backoffMax = 5 * time.Minute

// backoffFor is the wait after the n-th consecutive panic: a second,
// doubling, up to backoffMax.
func backoffFor(n int) time.Duration {
	if n < 1 {
		return 0
	}
	if n > 9 {
		return backoffMax
	}
	d := time.Second << (n - 1)
	if d > backoffMax {
		return backoffMax
	}
	return d
}

// onPanic is told of every panic a Guard recovers, with the loop's name,
// the count of consecutive ones and the panic's value; nil until SetOnPanic.
var onPanic atomic.Pointer[func(name string, consecutive int, value any)]

// SetOnPanic installs the hook the guards tell of their panics (the daemon
// installs the notifier's; nil removes it).  The hook runs on the loop's
// goroutine, after the log line: keep it short and never let it panic.
func SetOnPanic(fn func(name string, consecutive int, value any)) {
	if fn == nil {
		onPanic.Store(nil)
		return
	}
	onPanic.Store(&fn)
}
