package handlers

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// waitKnown polls get() until a real figure is cached (the background compute
// finished) or the deadline passes.  While the background compute is in flight
// get() returns not-known WITHOUT starting another compute (refreshing gate),
// so polling is safe.
func waitKnown(t *testing.T, c *communityHitsCache, compute func() (communityHitStats, error)) (communityHitStats, bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := c.get(time.Now(), compute); ok {
			return v, true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return communityHitStats{}, false
}

// waitSettled waits until no background refresh is in flight.
func waitSettled(c *communityHitsCache) {
	for i := 0; i < 500 && c.Refreshing(); i++ {
		time.Sleep(2 * time.Millisecond)
	}
}

// First call has nothing cached: the compute runs in the BACKGROUND (never on
// the request path — a large-DB scan must not block the page), so the first get
// is not-known and the figure appears once the background compute finishes.
func TestCommunityHitsCacheFirstComputeBackground(t *testing.T) {
	var c communityHitsCache
	var calls atomic.Int32
	ran := make(chan struct{}, 1)
	compute := func() (communityHitStats, error) {
		calls.Add(1)
		ran <- struct{}{}
		return communityHitStats{Count: 7, UniqueIP: 3}, nil
	}
	if v, ok := c.get(time.Now(), compute); ok {
		t.Fatalf("first get must be not-known (background compute), got %+v", v)
	}
	<-ran
	v, ok := waitKnown(t, &c, compute)
	if !ok || v.Count != 7 || v.UniqueIP != 3 {
		t.Fatalf("post-background get = %+v ok=%v, want 7/3 known", v, ok)
	}
	if calls.Load() != 1 {
		t.Fatalf("compute calls = %d, want 1", calls.Load())
	}
}

// A fresh cache entry is served from memory -- compute must NOT run again.
func TestCommunityHitsCacheFreshServesFromMemory(t *testing.T) {
	var c communityHitsCache
	var calls atomic.Int32
	compute := func() (communityHitStats, error) {
		calls.Add(1)
		return communityHitStats{Count: 1}, nil
	}
	now := time.Now()
	c.get(now, compute) // background prime
	if _, ok := waitKnown(t, &c, compute); !ok {
		t.Fatal("background prime never became known")
	}
	v, ok := c.get(now.Add(communityHitsTTL/2), compute)
	if !ok || v.Count != 1 {
		t.Fatalf("second get = %+v ok=%v", v, ok)
	}
	if calls.Load() != 1 {
		t.Fatalf("compute calls = %d, want 1 (cached)", calls.Load())
	}
}

// A stale entry is served immediately (old figure) while one background
// refresh recomputes; the next fresh read sees the new figure.
func TestCommunityHitsCacheStaleServesOldAndRefreshes(t *testing.T) {
	var c communityHitsCache
	var calls atomic.Int32
	done := make(chan struct{}, 1)
	compute := func() (communityHitStats, error) {
		n := calls.Add(1)
		if n > 1 {
			defer func() { done <- struct{}{} }()
			return communityHitStats{Count: 20}, nil
		}
		return communityHitStats{Count: 10}, nil
	}
	c.get(time.Now(), compute) // background prime (Count=10)
	if _, ok := waitKnown(t, &c, compute); !ok {
		t.Fatal("prime never became known")
	}

	stale := time.Now().Add(communityHitsTTL + time.Minute)
	v, ok := c.get(stale, compute)
	if !ok || v.Count != 10 {
		t.Fatalf("stale get should serve the OLD figure, got %+v ok=%v", v, ok)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("background refresh never ran")
	}
	waitSettled(&c)
	v, ok = c.get(time.Now(), compute) // refresh stamped wall-clock `at`
	if !ok || v.Count != 20 {
		t.Fatalf("post-refresh get = %+v ok=%v, want 20", v, ok)
	}
	if calls.Load() != 2 {
		t.Fatalf("compute calls = %d, want 2 (prime + one refresh)", calls.Load())
	}
}

// A failed compute leaves the figure unknown (template shows an em dash, not
// a fake zero) and a later call retries.
func TestCommunityHitsCacheErrorStaysUnknownAndRetries(t *testing.T) {
	var c communityHitsCache
	var calls atomic.Int32
	fail := atomic.Bool{}
	fail.Store(true)
	ran := make(chan struct{}, 2)
	compute := func() (communityHitStats, error) {
		calls.Add(1)
		defer func() { ran <- struct{}{} }()
		if fail.Load() {
			return communityHitStats{}, errors.New("db down")
		}
		return communityHitStats{Count: 5}, nil
	}
	if _, ok := c.get(time.Now(), compute); ok {
		t.Fatal("first get must be not-known (background)")
	}
	<-ran // background compute #1 ran (and failed)
	waitSettled(&c)
	c.mu.Lock()
	known := c.known
	c.mu.Unlock()
	if known {
		t.Fatal("errored compute must stay unknown")
	}

	fail.Store(false)
	if _, ok := c.get(time.Now(), compute); ok { // spawns background retry #2
		t.Fatal("retry get is not-known until the background retry finishes")
	}
	<-ran // retry #2 ran (and succeeded)
	v, ok := waitKnown(t, &c, compute)
	if !ok || v.Count != 5 {
		t.Fatalf("retry get = %+v ok=%v, want 5", v, ok)
	}
	if calls.Load() != 2 {
		t.Fatalf("compute calls = %d, want 2", calls.Load())
	}
}
