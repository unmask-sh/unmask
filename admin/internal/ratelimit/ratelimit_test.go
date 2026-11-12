package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestHitWithinAllowance(t *testing.T) {
	l := New()
	now := time.Unix(1000, 0)
	l.SetClock(func() time.Time { return now })
	spec := Spec{RequestsPerMin: 60, Burst: 10, WindowSec: 60}
	// 60r/m * 60s/60 + 10 = 70 hits stay hit=false; the 71st flips to hit=true.
	for i := 1; i <= 70; i++ {
		r := l.Hit("k1", spec)
		if r.Hit {
			t.Fatalf("hit=true at count=%d, want false (count=%d allowance=%d)", i, r.Count, r.Allowance)
		}
	}
	r := l.Hit("k1", spec)
	if !r.Hit {
		t.Fatalf("hit=false at count=71, want true (count=%d allowance=%d)", r.Count, r.Allowance)
	}
}

func TestSlidingWindow(t *testing.T) {
	l := New()
	t0 := time.Unix(1000, 0)
	clock := t0
	l.SetClock(func() time.Time { return clock })
	spec := Spec{RequestsPerMin: 60, Burst: 0, WindowSec: 60}
	for i := 0; i < 60; i++ {
		l.Hit("k1", spec)
	}
	if !l.Hit("k1", spec).Hit {
		t.Fatal("expected hit at 61")
	}
	// After the window slides, older hits are purged and hit=false returns.
	clock = t0.Add(120 * time.Second)
	if r := l.Hit("k1", spec); r.Hit {
		t.Fatalf("expected hit=false after window slide, got %+v", r)
	}
}

func TestKeyIsolation(t *testing.T) {
	l := New()
	now := time.Unix(1000, 0)
	l.SetClock(func() time.Time { return now })
	spec := Spec{RequestsPerMin: 1, Burst: 0, WindowSec: 60}
	// k1: 1 hit lands exactly on allowance (= 1*60/60=1, hit=false)
	if r := l.Hit("k1", spec); r.Hit {
		t.Fatalf("k1: hit=true at count=1, want false (allowance=%d)", r.Allowance)
	}
	// k1: 2nd hit flips to hit=true
	if !l.Hit("k1", spec).Hit {
		t.Fatal("k1: expected hit at count=2")
	}
	// k2 is independent (= still hit=false)
	if r := l.Hit("k2", spec); r.Hit {
		t.Fatal("k2 should be independent")
	}
}

func TestDisabledSpec(t *testing.T) {
	l := New()
	if r := l.Hit("k", Spec{}); r.Hit {
		t.Fatal("disabled spec should never hit")
	}
	if r := l.Hit("k", Spec{RequestsPerMin: 100}); r.Hit {
		t.Fatal("WindowSec=0 should disable")
	}
}

func TestPurgeStale(t *testing.T) {
	l := New()
	t0 := time.Unix(1000, 0)
	clock := t0
	l.SetClock(func() time.Time { return clock })
	spec := Spec{RequestsPerMin: 60, Burst: 0, WindowSec: 60}
	l.Hit("k1", spec)
	if l.Size() != 1 {
		t.Fatalf("size before purge=%d, want 1", l.Size())
	}
	clock = t0.Add(2 * time.Hour)
	l.Purge()
	if l.Size() != 0 {
		t.Fatalf("size after purge=%d, want 0 (stale entry should be dropped)", l.Size())
	}
}

func TestReset(t *testing.T) {
	l := New()
	now := time.Unix(1000, 0)
	l.SetClock(func() time.Time { return now })
	spec := Spec{RequestsPerMin: 1, Burst: 0, WindowSec: 60}
	l.Hit("k", spec)
	l.Hit("k", spec) // hit=true
	l.Reset("k")
	if r := l.Hit("k", spec); r.Hit {
		t.Fatalf("expected hit=false after Reset, got %+v", r)
	}
}

func TestEvictOldest(t *testing.T) {
	l := New()
	for i, last := range []int64{50, 10, 30, 20, 40} {
		l.m[string(rune('a'+i))] = &window{hits: []int64{last}}
	}
	l.evictOldest(2)
	if len(l.m) != 3 {
		t.Fatalf("want 3 keys after evicting 2, got %d", len(l.m))
	}
	if _, ok := l.m["b"]; ok {
		t.Error("key b (last=10) should have been evicted")
	}
	if _, ok := l.m["d"]; ok {
		t.Error("key d (last=20) should have been evicted")
	}
}

// A key-rotation flood is the case the table's bound exists for, and there
// every request is a new key.  Both bounding steps walk the whole table under
// the lock; when they ran once per new key, one check cost milliseconds and
// the forward-auth checks queued behind it timed out (which nginx answers by
// failing open).  The number of whole-table passes must not follow the number
// of new keys.  Counted, not timed: the passes are what cost.
func TestNewKeysDoNotEachWalkTheTable(t *testing.T) {
	spec := Spec{RequestsPerMin: 60, WindowSec: 60}
	for _, size := range []int{rlSweepThreshold, rlHardCap} {
		l := New()
		clock := time.Unix(1000, 0)
		l.SetClock(func() time.Time { return clock })
		// Live keys: all hit "now", so no sweep can free any of them.
		for i := 0; i < size; i++ {
			l.m[fmt.Sprintf("2001:db8:1:2::%x|default", i)] = &window{hits: []int64{0}}
		}
		const fresh = 2000
		for i := 0; i < fresh; i++ {
			l.Hit(fmt.Sprintf("2001:db8:9:%x::1|default", i), spec)
		}
		// One sweep (it has never run) and at most one eviction.
		if l.passes > 2 {
			t.Errorf("table of %d: %d new keys cost %d whole-table passes, want at most 2", size, fresh, l.passes)
		}
		if got := l.Size(); got > rlHardCap {
			t.Errorf("table of %d: grew to %d, over the hard cap %d", size, got, rlHardCap)
		}
	}
}

// The hard cap holds through a flood far longer than one eviction batch, and
// a client that keeps sending is not the one evicted: eviction takes the keys
// whose last hit is oldest, which are the flood's own one-shot keys.
func TestFloodKeepsTheCapAndTheActiveKey(t *testing.T) {
	spec := Spec{RequestsPerMin: 60, WindowSec: 60}
	l := New()
	clock := time.Unix(1000, 0)
	l.SetClock(func() time.Time { return clock })
	const active = "203.0.113.7|default"
	const flood = rlHardCap + 3*rlEvictBatch
	for i := 0; i < flood; i++ {
		if i%1000 == 0 {
			clock = clock.Add(time.Second) // 1,000 new keys a second
			l.Hit(active, spec)
		}
		l.Hit(fmt.Sprintf("2001:db8:%x:%x::1|default", i>>16, i&0xffff), spec)
		if n := len(l.m); n > rlHardCap {
			t.Fatalf("after %d new keys the table holds %d, over the hard cap %d", i+1, n, rlHardCap)
		}
	}
	w, ok := l.m[active]
	if !ok {
		t.Fatal("the key that kept sending was evicted")
	}
	// Its count is the hits inside the window, not reset by an eviction.
	if len(w.hits) < 2 {
		t.Errorf("the active key holds %d hits, want its window intact", len(w.hits))
	}
	// 3+ batches past the cap is a handful of passes, not one per key.
	if l.passes > 40 {
		t.Errorf("%d new keys cost %d whole-table passes", flood, l.passes)
	}
}

// Stale keys still go: once the sweep interval has passed, a new key at the
// threshold drops every window idle past rlStaleSeconds.
func TestSweepStillFreesStaleKeys(t *testing.T) {
	spec := Spec{RequestsPerMin: 60, WindowSec: 60}
	l := New()
	clock := time.Unix(1000, 0)
	l.SetClock(func() time.Time { return clock })
	for i := 0; i < rlSweepThreshold; i++ {
		l.m[fmt.Sprintf("198.51.100.%d|z%d", i%250, i)] = &window{hits: []int64{0}}
	}
	l.Hit("first-new-key", spec) // sweeps at t=0: nothing is stale yet
	if got := l.Size(); got != rlSweepThreshold+1 {
		t.Fatalf("size after the first sweep = %d, want %d (nothing stale yet)", got, rlSweepThreshold+1)
	}
	clock = clock.Add((rlStaleSeconds + rlSweepEverySec + 1) * time.Second)
	l.Hit("second-new-key", spec)
	if got := l.Size(); got != 1 {
		t.Errorf("size after the stale sweep = %d, want 1 (only the new key)", got)
	}
}
