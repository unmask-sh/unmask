package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestWorkerGroupStopsAndWaits: a worker that watches the context ends at
// Cancel and Wait sees it; one that does not is reported at the limit, not
// waited for forever.
func TestWorkerGroupStopsAndWaits(t *testing.T) {
	g := newWorkerGroup(context.Background())
	var ticks, ended atomic.Int32
	g.Go("ticker", func(ctx context.Context) {
		defer ended.Add(1)
		tk := time.NewTicker(time.Millisecond)
		defer tk.Stop()
		for tick(ctx, tk) {
			ticks.Add(1)
		}
	})
	g.Go("sleeper", func(ctx context.Context) {
		defer ended.Add(1)
		if sleepCtx(ctx, time.Hour) {
			t.Error("sleepCtx waited the hour out")
		}
	})
	g.Go("panics", func(context.Context) { panic("one bad worker") })
	time.Sleep(20 * time.Millisecond)
	g.Cancel()
	if !g.Wait(5 * time.Second) {
		t.Fatal("the workers did not stop at Cancel")
	}
	if ended.Load() != 2 || ticks.Load() == 0 {
		t.Fatalf("ended=%d ticks=%d", ended.Load(), ticks.Load())
	}

	deaf := newWorkerGroup(context.Background())
	release := make(chan struct{})
	deaf.Go("deaf", func(context.Context) { <-release })
	deaf.Cancel()
	if deaf.Wait(30 * time.Millisecond) {
		t.Fatal("Wait returned true with a worker still running")
	}
	close(release)
	if !deaf.Wait(5 * time.Second) {
		t.Fatal("the released worker was not seen ending")
	}
}
