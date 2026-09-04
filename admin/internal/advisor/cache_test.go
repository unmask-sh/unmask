package advisor

import (
	"context"
	"testing"
	"time"
)

// The cached list is served without a recompute inside cacheFresh, applies
// the operator's exclusions on the way out (a dismiss needs no recompute),
// and is per database.
func TestCachedCandidates(t *testing.T) {
	ResetCandidateCache()
	t.Cleanup(ResetCandidateCache)
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	for i := 0; i < 6; i++ {
		insertEvent(t, d, "203.0.113.10", "t13d_a", "serve", "curl/8", "")
	}
	first, at, err := CachedCandidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Target != "203.0.113.10" || time.Since(at) > time.Minute {
		t.Fatalf("first list: %+v at %v", first, at)
	}
	// A new candidate does not show until the list is refreshed ...
	for i := 0; i < 6; i++ {
		insertEvent(t, d, "203.0.113.11", "t13d_b", "serve", "curl/8", "")
	}
	second, at2, _ := CachedCandidates(context.Background(), d, nil, Exclusions{}, opt)
	if len(second) != 1 || !at2.Equal(at) {
		t.Fatalf("inside cacheFresh the list is served as is: %+v", second)
	}
	// ... but a dismissal takes effect at once, without a recompute.
	excluded, at3, _ := CachedCandidates(context.Background(), d, nil, Exclusions{DismissedIP: map[string]bool{"203.0.113.10": true}}, opt)
	if len(excluded) != 0 || !at3.Equal(at) {
		t.Fatalf("exclusions apply on the way out: %+v", excluded)
	}
	// Forgetting the cache (what a restart does) recomputes.
	ResetCandidateCache()
	third, at4, _ := CachedCandidates(context.Background(), d, nil, Exclusions{}, opt)
	if len(third) != 2 || !at4.After(at) {
		t.Fatalf("after a reset the list is recomputed: %+v", third)
	}
	// Another database has its own list.
	d2 := newTestDB(t)
	other, _, _ := CachedCandidates(context.Background(), d2, nil, Exclusions{}, opt)
	if len(other) != 0 {
		t.Fatalf("the cache must be per database, got %+v", other)
	}
	// Older than cacheFresh: served at once, refreshed behind.
	candCache.Lock()
	for _, e := range candCache.m {
		e.at = time.Now().Add(-2 * cacheFresh)
	}
	candCache.Unlock()
	for i := 0; i < 6; i++ {
		insertEvent(t, d, "203.0.113.12", "t13d_c", "serve", "curl/8", "")
	}
	stale, _, _ := CachedCandidates(context.Background(), d, nil, Exclusions{}, opt)
	if len(stale) != 2 {
		t.Fatalf("a stale list is served as is while the refresh runs: %+v", stale)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		fresh, _, _ := CachedCandidates(context.Background(), d, nil, Exclusions{}, opt)
		if len(fresh) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the background refresh never landed: %+v", fresh)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
