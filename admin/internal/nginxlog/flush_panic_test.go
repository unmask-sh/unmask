package nginxlog

import (
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/safe"
)

// A panic in a flush ends that flush, not the loop: the counters stay in
// memory and the next tick, after the guard's wait, writes them.  Through
// 0.1.53 the loop ended at the first panic, and the counters grew in memory
// for the life of the process.
func TestFlushLoopSurvivesAPanic(t *testing.T) {
	r, d := cookieIPReader(t)
	r.stop = make(chan struct{})
	r.doneB = make(chan struct{})
	panics := make(chan int, 8)
	safe.SetOnPanic(func(name string, n int, _ any) {
		if name == "nginxlog-flush" {
			panics <- n
		}
	})
	t.Cleanup(func() { safe.SetOnPanic(nil) })
	// The first flush panics; the ones after it run.
	fired := false
	r.beforeFlush = func() {
		if !fired {
			fired = true
			panic("boom")
		}
	}
	old := flushEvery
	flushEvery = 20 * time.Millisecond
	t.Cleanup(func() { flushEvery = old })

	go r.flushLoop()
	select {
	case n := <-panics:
		if n != 1 {
			t.Errorf("consecutive = %d", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no flush panicked")
	}
	// A counter of a past minute: a tick's flush (not a final one) writes
	// only the minutes that are over.
	r.mu.Lock()
	r.cookieIPBuckets[cookieIPKey{minute: time.Now().Unix()/60 - 2, site: "s1", ip: "1.2.3.4", kind: "pow"}] = &cookieIPBucket{cnt: 1, judged: 1, ja4: "t13d_a", ua: "UA-A"}
	r.mu.Unlock()
	total := func() int {
		var n int
		if err := d.QueryRow(`SELECT COALESCE(SUM(cnt), 0) FROM unmask_cookie_ip_minute`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// The wait after one panic is a second; the tick after it flushes.
	deadline := time.Now().Add(15 * time.Second)
	for total() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	close(r.stop)
	select {
	case <-r.doneB:
	case <-time.After(10 * time.Second):
		t.Fatal("the flush loop did not stop")
	}
	if total() != 1 {
		t.Fatalf("the loop did not write the counter after the panic: %d", total())
	}
}
