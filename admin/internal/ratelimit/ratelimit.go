// Package ratelimit: sliding-window rate limiter.
//
// Intended usage: count hits per client (= IP × JA4 × zone) inside the
// auth_request / forward-auth-mode subrequest (= /_unmask/check).  When the
// threshold is exceeded, branch to the challenge / block path via 401 / 429.
// Native mode uses nginx `limit_req`, so it does not call this package.
//
// Implementation: hold a list of hit timestamps per key in an in-memory map,
// and lazy-purge timestamps outside the window on the next Hit.  Concurrency-safe (= sync.Mutex).
//
// No persistence (= reset on restart).  If we extend to SQLite-backed in
// v0.2, Hit will hydrate the past window from the events table.
package ratelimit

import (
	"sort"
	"sync"
	"time"
)

// Limiter: concurrency-safe sliding-window counter.
type Limiter struct {
	mu    sync.Mutex
	m     map[string]*window
	nowFn func() time.Time // for testability.  Defaults to time.Now.
	base  time.Time        // captured when the clock is set; window math uses elapsed-since-base so it rides the monotonic clock (RL-1).
}

type window struct {
	hits []int64 // list of hit timestamps in unix seconds.  Oldest first (= append-only + head trim).
}

// New: return a fresh Limiter.
func New() *Limiter {
	l := &Limiter{
		m:     make(map[string]*window),
		nowFn: time.Now,
	}
	l.base = l.nowFn()
	return l
}

// SetClock: inject a clock for tests.
func (l *Limiter) SetClock(fn func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nowFn = fn
	l.base = fn()
}

// nowSec returns seconds elapsed since base.  It is built on time.Time.Sub,
// which uses the monotonic clock reading when present (= production time.Now),
// so a wall-clock step (e.g. NTP correction) cannot move the rate window
// backwards (RL-1).  Callers hold l.mu.
func (l *Limiter) nowSec() int64 {
	return int64(l.nowFn().Sub(l.base) / time.Second)
}

const (
	// rlSweepThreshold: map size above which Hit evicts stale keys before
	// inserting a new one.  rlStaleSeconds: a key whose newest hit is older than
	// this is past any reasonable rate window, so it's safe to drop.
	rlSweepThreshold = 100_000
	rlStaleSeconds   = 600
	// rlHardCap: absolute ceiling on map size.  If sweeping stale keys still
	// leaves us at/above this (= every window is inside the stale window, i.e. an
	// active key-rotation flood), evict the oldest keys so memory stays bounded (RL-2).
	rlHardCap = 120_000
)

// sweepStale drops windows idle longer than rlStaleSeconds.  Caller holds l.mu.
func (l *Limiter) sweepStale(now int64) {
	cutoff := now - rlStaleSeconds
	for k, w := range l.m {
		if len(w.hits) == 0 || w.hits[len(w.hits)-1] < cutoff {
			delete(l.m, k)
		}
	}
}

// evictOldest removes the n keys whose most-recent hit is oldest.  Caller holds
// l.mu.  This is the hard backstop for RL-2: it runs only when sweepStale can't
// get the map under rlHardCap, i.e. under an active key-rotation flood.  Evicted
// keys are recreated on their next hit (= counter reset), trading exactness for
// a bounded map.
func (l *Limiter) evictOldest(n int) {
	if n <= 0 {
		return
	}
	type keyAge struct {
		key  string
		last int64
	}
	ages := make([]keyAge, 0, len(l.m))
	for k, w := range l.m {
		var last int64
		if len(w.hits) > 0 {
			last = w.hits[len(w.hits)-1]
		}
		ages = append(ages, keyAge{k, last})
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].last < ages[j].last })
	if n > len(ages) {
		n = len(ages)
	}
	for i := 0; i < n; i++ {
		delete(l.m, ages[i].key)
	}
}

// Spec: rate spec for a single zone.  Built from settings.RateZone.
type Spec struct {
	RequestsPerMin int
	Burst          int
	WindowSec      int
}

// Result: judgement from Hit.
type Result struct {
	Hit       bool // true if the threshold is exceeded
	Count     int  // hit count within the window (= includes this hit)
	Allowance int  // allowed count (= RequestsPerMin * WindowSec/60 + Burst)
	WindowSec int  // window seconds used for evaluation
}

// Hit: record + judge a single hit for key.
//
// If Spec.RequestsPerMin <= 0 or WindowSec <= 0, treat as disabled and
// return Result{} (= no counting, always hit=false).  For "rate-limit feature OFF."
func (l *Limiter) Hit(key string, spec Spec) Result {
	if spec.RequestsPerMin <= 0 || spec.WindowSec <= 0 {
		return Result{}
	}
	allowance := spec.RequestsPerMin*spec.WindowSec/60 + spec.Burst
	if allowance <= 0 {
		// Both burst and rate are effectively 0: always treat as a hit.  A degenerate but possible config.
		allowance = 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowSec()
	cutoff := now - int64(spec.WindowSec)

	w, ok := l.m[key]
	if !ok {
		// Bound the map: a client rotating the key (e.g. spoofed JA4 in the key)
		// would otherwise add an entry per request forever = OOM.  When the map
		// is large, evict keys idle past any reasonable window before adding.
		if len(l.m) >= rlSweepThreshold {
			l.sweepStale(now)
			if len(l.m) >= rlHardCap {
				l.evictOldest(len(l.m) - rlHardCap + 1)
			}
		}
		w = &window{hits: make([]int64, 0, 16)}
		l.m[key] = w
	}
	// purge old hits (= head entries outside the window).
	idx := 0
	for idx < len(w.hits) && w.hits[idx] < cutoff {
		idx++
	}
	if idx > 0 {
		w.hits = w.hits[idx:]
	}
	w.hits = append(w.hits, now)
	count := len(w.hits)
	return Result{
		Hit:       count > allowance,
		Count:     count,
		Allowance: allowance,
		WindowSec: spec.WindowSec,
	}
}

// Reset: clear the counter for key.  For tests / manual unblock.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, key)
}

// Purge: GC entries that have had no hit for 1 hour.  Intended to be called periodically (= every minute).
func (l *Limiter) Purge() {
	const stale = 3600 // 1h
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowSec()
	cutoff := now - stale
	for k, w := range l.m {
		if len(w.hits) == 0 || w.hits[len(w.hits)-1] < cutoff {
			delete(l.m, k)
		}
	}
}

// Size: return the current entry count for monitoring / metrics.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}
