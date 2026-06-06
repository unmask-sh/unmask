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
	"sync"
	"time"
)

// Limiter: concurrency-safe sliding-window counter.
type Limiter struct {
	mu    sync.Mutex
	m     map[string]*window
	nowFn func() time.Time // for testability.  Defaults to time.Now.
}

type window struct {
	hits []int64 // list of hit timestamps in unix seconds.  Oldest first (= append-only + head trim).
}

// New: return a fresh Limiter.
func New() *Limiter {
	return &Limiter{
		m:     make(map[string]*window),
		nowFn: time.Now,
	}
}

// SetClock: inject a clock for tests.
func (l *Limiter) SetClock(fn func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nowFn = fn
}

const (
	// rlSweepThreshold: map size above which Hit evicts stale keys before
	// inserting a new one.  rlStaleSeconds: a key whose newest hit is older than
	// this is past any reasonable rate window, so it's safe to drop.
	rlSweepThreshold = 100_000
	rlStaleSeconds   = 600
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

	now := l.nowFn().Unix()
	cutoff := now - int64(spec.WindowSec)

	w, ok := l.m[key]
	if !ok {
		// Bound the map: a client rotating the key (e.g. spoofed JA4 in the key)
		// would otherwise add an entry per request forever = OOM.  When the map
		// is large, evict keys idle past any reasonable window before adding.
		if len(l.m) >= rlSweepThreshold {
			l.sweepStale(now)
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
	now := l.nowFn().Unix()
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
