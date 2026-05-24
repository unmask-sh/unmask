package handlers

import (
	"sync"
	"time"
)

// serveDedupe suppresses duplicate `serve` event inserts that happen when one
// underlying challenge fire reaches ServeChallenge twice within milliseconds.
// Observed on tool1-jp: real browser clients (= Chrome prerender / accidental
// double-click / GCP HTTPS LB occasional retry) request the same URL twice
// inside a few tens of milliseconds, and both reach the handler.  Both hits
// write byte-identical rows that only differ in id + timestamp, and they
// dirty the hunt session view (= "serve › serve › load › bv_pow") even
// though they represent one user-visible challenge fire.
//
// Dedupe key is (host, beacon_token).  beacon_token is regenerated per
// request, but a duplicate request from the same browser tab also produces
// the same payload contents in practice, and the dedupe window is short
// enough that two genuine consecutive challenge serves to the same client
// (= legitimate reload of a different URL) get different tokens and pass.
//
// Implementation: a tiny TTL map.  Lock granularity is process-wide because
// the call rate is bounded by serve event throughput, not by the request
// rate at large.  Cleanup is opportunistic (= triggered on bump-and-grow)
// to avoid a background goroutine on a feature that doesn't justify one.
var serveDedupe = newDedupeCache(2 * time.Second)

type dedupeCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

func newDedupeCache(ttl time.Duration) *dedupeCache {
	return &dedupeCache{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
}

// shouldRecord returns true when the caller should write the event, false
// when this key was already recorded within the TTL window.  Idempotent on
// subsequent calls until the TTL elapses.
func (c *dedupeCache) shouldRecord(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if t, ok := c.seen[key]; ok && now.Sub(t) < c.ttl {
		return false
	}
	c.seen[key] = now
	// Opportunistic cleanup -- the seen map should not grow unbounded.
	// Triggered only when it crosses a small threshold so the common path
	// stays a single map write.
	if len(c.seen) > 1024 {
		cutoff := now.Add(-2 * c.ttl)
		for k, t := range c.seen {
			if t.Before(cutoff) {
				delete(c.seen, k)
			}
		}
	}
	return true
}
