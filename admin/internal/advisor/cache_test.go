package advisor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
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

// The list is computed off the request.  A request that finds no list starts
// the computation and, when it has not finished in computeWait, answers
// "being computed"; the status says so; the next request gets the list.
func TestCandidatesComputedBehind(t *testing.T) {
	ResetCandidateCache()
	t.Cleanup(ResetCandidateCache)
	defer SetComputeWaitForTest(0)()
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	for i := 0; i < 6; i++ {
		insertEvent(t, d, "203.0.113.10", "t13d_a", "serve", "curl/8", "")
	}
	_, _, err := CachedCandidates(context.Background(), d, nil, Exclusions{}, opt)
	if !errors.Is(err, ErrComputing) {
		t.Fatalf("a request with no list must answer ErrComputing, got %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := CandidateStatus(d, opt)
		if !st.At.IsZero() {
			break
		}
		if st.Err != "" || time.Now().After(deadline) {
			t.Fatalf("the computation did not land: %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cands, _, err := CachedCandidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil || len(cands) == 0 || cands[0].Target != "203.0.113.10" {
		t.Fatalf("the computed list is not served: %v %+v", err, cands)
	}
	if st := CandidateStatus(d, opt); st.Computing || st.Err != "" {
		t.Errorf("status after the list landed: %+v", st)
	}
}

// A computation that fails is reported, not waited for.
func TestCandidatesComputeFailureIsReported(t *testing.T) {
	ResetCandidateCache()
	t.Cleanup(ResetCandidateCache)
	// A database with no schema: the engine's query fails at once.
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/empty.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	_, _, err = CachedCandidates(context.Background(), d, nil, Exclusions{}, Options{WindowMinutes: 60})
	if err == nil || errors.Is(err, ErrComputing) {
		t.Fatalf("a failed computation must surface its error, got %v", err)
	}
	if st := CandidateStatus(d, Options{WindowMinutes: 60}); st.Err == "" || st.Computing {
		t.Errorf("status after a failure: %+v", st)
	}
}
