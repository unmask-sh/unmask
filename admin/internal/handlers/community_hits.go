// "Community Bans impact" figures (= how much traffic the hub-derived BANs
// actually stopped here in the past 30 days).  The underlying query walks
// every serve row in the 30-day window, so it must never run per page load:
// measured 5.0s raw / 0.8s with the LIKE prefilter on a 550k-row fleet DB.
// A small TTL cache serves the figures from memory and refreshes them at most
// once per interval, stale-while-revalidate style.
package handlers

import (
	"context"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// communityHitStats: past-30d serve events that carried
// ban_source=community_bans, and across how many distinct IPs.
type communityHitStats struct {
	Count    int
	UniqueIP int
}

const communityHitsTTL = 15 * time.Minute

// communityHitsCache memoizes communityHitStats.  A fresh value is returned
// from memory; a stale one is returned immediately while ONE background
// goroutine recomputes; only the very first request (nothing cached yet) pays
// the query synchronously.
type communityHitsCache struct {
	mu         sync.Mutex
	val        communityHitStats
	known      bool      // val holds a real computed figure
	at         time.Time // when val was computed
	refreshing bool      // a refresh goroutine is in flight
}

// get returns the cached figures and whether a real figure is known (false ->
// the template renders an em dash, never a fake zero).  compute must be safe
// to call from another goroutine.
func (c *communityHitsCache) get(now time.Time, compute func() (communityHitStats, error)) (communityHitStats, bool) {
	c.mu.Lock()
	fresh := c.known && now.Sub(c.at) < communityHitsTTL
	if fresh {
		v := c.val
		c.mu.Unlock()
		return v, true
	}
	if c.known {
		// Stale: serve the old figure right away, refresh once in background.
		if !c.refreshing {
			c.refreshing = true
			go c.refresh(compute)
		}
		v := c.val
		c.mu.Unlock()
		return v, true
	}
	if c.refreshing {
		// First computation is already underway on another request; don't
		// stack a second full scan behind it.
		c.mu.Unlock()
		return communityHitStats{}, false
	}
	// Nothing cached yet: compute in the BACKGROUND, never on the request path.
	// The 30-day impact scan reads payload_json for every serve row in the
	// window (millions of rows, ~38s on a multi-million-row production DB), so blocking the
	// first Community Bans page load on it made the tab hang for tens of
	// seconds.  Return "not known yet" so the page renders instantly; a reload
	// after the background scan finishes shows the figure.
	c.refreshing = true
	c.mu.Unlock()
	go c.refresh(compute)
	return communityHitStats{}, false
}

// Refreshing reports whether a background impact-figure computation is in
// flight, so the template can say "computing…" instead of a bare em dash that
// reads as "no data".
func (c *communityHitsCache) Refreshing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshing
}

func (c *communityHitsCache) refresh(compute func() (communityHitStats, error)) {
	v, err := compute()
	c.mu.Lock()
	c.refreshing = false
	if err == nil {
		c.val, c.known, c.at = v, true, time.Now()
	}
	c.mu.Unlock()
}

// communityBansHits30d runs the impact query.  The LIKE prefilter lets the
// scan skip the JSON parse on the overwhelming majority of rows, which never
// mention community_bans (5.0s -> 0.8s measured); json_extract stays as the
// authoritative predicate so a stray substring match can't inflate the count.
func communityBansHits30d(ctx context.Context, d *db.DB) (communityHitStats, error) {
	var jsonExpr, dateExpr string
	if d.Driver == "sqlite" {
		jsonExpr = `json_extract(payload_json, '$.ban_source')`
		dateExpr = `date_created >= datetime('now', '-30 days')`
	} else {
		jsonExpr = `JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.ban_source'))`
		dateExpr = `date_created >= DATE_SUB(NOW(), INTERVAL 30 DAY)`
	}
	// Generous budget: this runs only in the background (never on the request
	// path) and at most once per communityHitsTTL, so a slow 30-day scan on a
	// large DB should be allowed to finish and populate the cache rather than
	// time out at 30s and leave the figure unknown forever (measured 38s on the
	// 6.6M-row web1-us DB).
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	var s communityHitStats
	err := d.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT ip_address)
	   FROM unmask_event
	  WHERE phase = 'serve'
	    AND payload_json LIKE '%community_bans%'
	    AND `+jsonExpr+` = 'community_bans'
	    AND `+dateExpr).Scan(&s.Count, &s.UniqueIP)
	return s, err
}
