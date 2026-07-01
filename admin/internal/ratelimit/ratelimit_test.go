package ratelimit

import (
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
