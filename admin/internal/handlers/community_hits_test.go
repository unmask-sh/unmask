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
// a fake zero).  It is not retried on the next call: a scan that outlasted
// its budget would do so again a few seconds later, and retrying on every
// poll kept the page's spinner forever while the database was read end to
// end, two minutes at a time.  The figure reads "unavailable" until the retry
// window (communityHitsRetryAfter) opens; the call after that retries.
func TestCommunityHitsCacheErrorStaysUnknownAndRetriesLater(t *testing.T) {
	var c communityHitsCache
	var calls atomic.Int32
	fail := atomic.Bool{}
	fail.Store(true)
	ran := make(chan struct{}, 2)
	compute := func() (communityHitStats, error) {
		calls.Add(1)
		defer func() { ran <- struct{}{} }()
		if fail.Load() {
			return communityHitStats{}, errors.New("context deadline exceeded")
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

	// Inside the retry window: not known, nothing dispatched, and the state
	// the page needs to say why is "unavailable", not "computing".
	fail.Store(false)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if _, ok := c.get(now, compute); ok {
			t.Fatal("a get inside the retry window must be not-known")
		}
	}
	if c.Refreshing() {
		t.Fatal("a get inside the retry window must not dispatch another scan")
	}
	if !c.Unavailable(now) {
		t.Fatal("inside the retry window the figure must read unavailable")
	}
	if calls.Load() != 1 {
		t.Fatalf("compute calls = %d, want 1 (no retry inside the window)", calls.Load())
	}

	// The window opens: the next get retries in the background.
	later := now.Add(communityHitsRetryAfter + time.Minute)
	if _, ok := c.get(later, compute); ok { // spawns background retry #2
		t.Fatal("retry get is not-known until the background retry finishes")
	}
	if c.Unavailable(later) {
		t.Fatal("a retry in flight is computing, not unavailable")
	}
	<-ran // retry #2 ran (and succeeded)
	v, ok := waitKnown(t, &c, compute)
	if !ok || v.Count != 5 {
		t.Fatalf("retry get = %+v ok=%v, want 5", v, ok)
	}
	if calls.Load() != 2 {
		t.Fatalf("compute calls = %d, want 2", calls.Load())
	}
	if c.Unavailable(time.Now()) {
		t.Fatal("a success clears the failure")
	}
}

// A stale figure whose refresh fails keeps serving the old figure, and the
// next stale reads inside the retry window do not dispatch another refresh.
func TestCommunityHitsCacheStaleRefreshFailureKeepsOldFigureAndWaits(t *testing.T) {
	var c communityHitsCache
	var calls atomic.Int32
	fail := atomic.Bool{}
	ran := make(chan struct{}, 3)
	compute := func() (communityHitStats, error) {
		n := calls.Add(1)
		defer func() { ran <- struct{}{} }()
		if fail.Load() {
			return communityHitStats{}, errors.New("context deadline exceeded")
		}
		return communityHitStats{Count: int(n) * 10}, nil
	}
	c.get(time.Now(), compute) // background prime (Count=10)
	<-ran
	if _, ok := waitKnown(t, &c, compute); !ok {
		t.Fatal("prime never became known")
	}

	fail.Store(true)
	stale := time.Now().Add(communityHitsTTL + time.Minute)
	if v, ok := c.get(stale, compute); !ok || v.Count != 10 { // dispatches refresh #2, which fails
		t.Fatalf("stale get should serve the OLD figure, got %+v ok=%v", v, ok)
	}
	<-ran
	waitSettled(&c)
	fail.Store(false)
	for i := 0; i < 3; i++ {
		if v, ok := c.get(stale.Add(time.Minute), compute); !ok || v.Count != 10 {
			t.Fatalf("stale get inside the retry window = %+v ok=%v, want the old 10", v, ok)
		}
	}
	if c.Refreshing() || calls.Load() != 2 {
		t.Fatalf("stale gets inside the retry window dispatched a refresh (calls=%d)", calls.Load())
	}
	if c.Unavailable(stale.Add(time.Minute)) {
		t.Fatal("a known (if old) figure is never unavailable")
	}

	later := stale.Add(communityHitsRetryAfter + time.Minute)
	if v, ok := c.get(later, compute); !ok || v.Count != 10 { // dispatches refresh #3
		t.Fatalf("get after the window = %+v ok=%v, want the old 10 while #3 runs", v, ok)
	}
	<-ran
	waitSettled(&c)
	if v, ok := c.get(time.Now(), compute); !ok || v.Count != 30 {
		t.Fatalf("post-retry get = %+v ok=%v, want 30", v, ok)
	}
	if calls.Load() != 3 {
		t.Fatalf("compute calls = %d, want 3", calls.Load())
	}
}
