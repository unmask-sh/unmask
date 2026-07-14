package handlers

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// First call has nothing cached: compute runs inline and the figure is known.
func TestCommunityHitsCacheFirstComputeInline(t *testing.T) {
	var c communityHitsCache
	var calls atomic.Int32
	v, ok := c.get(time.Now(), func() (communityHitStats, error) {
		calls.Add(1)
		return communityHitStats{Count: 7, UniqueIP: 3}, nil
	})
	if !ok || v.Count != 7 || v.UniqueIP != 3 {
		t.Fatalf("first get = %+v ok=%v, want 7/3 known", v, ok)
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
	c.get(now, compute)
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
	c.get(time.Now(), compute) // prime (Count=10)

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
	fail := true
	compute := func() (communityHitStats, error) {
		calls.Add(1)
		if fail {
			return communityHitStats{}, errors.New("db down")
		}
		return communityHitStats{Count: 5}, nil
	}
	if _, ok := c.get(time.Now(), compute); ok {
		t.Fatal("errored compute must stay unknown")
	}
	fail = false
	v, ok := c.get(time.Now(), compute)
	if !ok || v.Count != 5 {
		t.Fatalf("retry get = %+v ok=%v, want 5", v, ok)
	}
	if calls.Load() != 2 {
		t.Fatalf("compute calls = %d, want 2", calls.Load())
	}
}
