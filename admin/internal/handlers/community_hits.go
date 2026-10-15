// "Community Bans impact" figures (= how much traffic the shared feed
// actually stopped here in the past 30 days).  The underlying query walks
// every serve row in the 30-day window, so it must never run per page load:
// measured 5.0s raw / 0.8s with the LIKE prefilter on a 550k-row fleet DB.
// A small TTL cache serves the figures from memory and refreshes them at most
// once per interval, stale-while-revalidate style.
package handlers

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// communityHitStats: past-30d serve events that the shared feed sent to a
// challenge (force_reason=community_bans), and across how many distinct IPs.
type communityHitStats struct {
	Count    int
	UniqueIP int
}

const communityHitsTTL = 15 * time.Minute

// communityHitsBudget is how long one 30-day scan may run.  Generous: it runs
// only in the background (never on the request path) and at most once per
// communityHitsTTL, so a slow scan on a large database is allowed to finish
// and populate the cache rather than time out at a page's budget.
const communityHitsBudget = 120 * time.Second

// communityHitsRetryAfter is how long a scan that failed keeps the figure
// "unavailable" before another scan is tried.  A scan that outlasted its
// budget on this database would do so again a few seconds later: retrying on
// the next poll meant the page's spinner never resolved and the database was
// read end to end, two minutes at a time, for as long as the page stayed
// open.  One try an hour bounds that; the page says why the figure is missing.
const communityHitsRetryAfter = time.Hour

// communityHitsCache memoizes communityHitStats.  A fresh value is returned
// from memory; a stale one is returned immediately while ONE background
// goroutine recomputes; the first request (nothing cached yet) dispatches the
// scan to the background and reports the figure as not known.
type communityHitsCache struct {
	mu         sync.Mutex
	val        communityHitStats
	known      bool      // val holds a real computed figure
	at         time.Time // when val was computed
	refreshing bool      // a refresh goroutine is in flight
	failedAt   time.Time // when the last compute failed; zero once one succeeds
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
	backoff := c.backingOff(now)
	if c.known {
		// Stale: serve the old figure right away, refresh once in background
		// -- unless the last refresh failed a short while ago, in which case
		// the old figure stands until the retry window opens.
		if !c.refreshing && !backoff {
			c.refreshing = true
			go c.refresh(compute)
		}
		v := c.val
		c.mu.Unlock()
		return v, true
	}
	if c.refreshing || backoff {
		// First computation is already underway on another request (don't
		// stack a second full scan behind it), or it failed recently and the
		// retry window has not opened: not known, and no new scan.
		c.mu.Unlock()
		return communityHitStats{}, false
	}
	// Nothing cached yet: compute in the BACKGROUND, never on the request path.
	// The 30-day impact scan reads payload_json for every serve row in the
	// window (millions of rows on a busy install), so blocking the first
	// Community Bans page load on it made the tab hang for tens of seconds.
	// Return "not known yet" so the page renders instantly; the page polls and
	// shows the figure when the background scan finishes.
	c.refreshing = true
	c.mu.Unlock()
	go c.refresh(compute)
	return communityHitStats{}, false
}

// backingOff: the last compute failed less than communityHitsRetryAfter ago.
// Caller holds mu.
func (c *communityHitsCache) backingOff(now time.Time) bool {
	return !c.failedAt.IsZero() && now.Sub(c.failedAt) < communityHitsRetryAfter
}

// Refreshing reports whether a background impact-figure computation is in
// flight, so the template can say "computing…" instead of a bare em dash that
// reads as "no data".
func (c *communityHitsCache) Refreshing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshing
}

// Unavailable reports that no figure is known because the last scan failed
// (its budget ran out on a large database) and the retry window has not
// opened yet: the page shows an em dash with the reason, and stops polling.
func (c *communityHitsCache) Unavailable(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.known && !c.refreshing && c.backingOff(now)
}

func (c *communityHitsCache) refresh(compute func() (communityHitStats, error)) {
	v, err := compute()
	c.mu.Lock()
	c.refreshing = false
	if err == nil {
		c.val, c.known, c.at = v, true, time.Now()
		c.failedAt = time.Time{}
	} else {
		c.failedAt = time.Now()
	}
	c.mu.Unlock()
	if err != nil {
		// The only place the failure is visible besides the page: the scan is
		// a background goroutine with no request to answer.
		log.Printf("community bans: the 30-day impact scan did not finish: %v (the page shows no figure; next try in %s)", err, communityHitsRetryAfter)
	}
}

// communityBansHits30d runs the impact query: the serve events of the window
// that the shared feed sent to a challenge.  A feed hit is recorded as
// force_reason=community_bans (the HTML and the non-HTML challenge both name
// it from the matcher); the feed is never copied into unmask_ban, so no event
// carries it as a ban source.  The LIKE prefilter lets the scan skip the JSON
// parse on the overwhelming majority of rows, which never mention
// community_bans (5.0s -> 0.8s measured); json_extract stays as the
// authoritative predicate so a stray substring match can't inflate the count.
func communityBansHits30d(ctx context.Context, d *db.DB) (communityHitStats, error) {
	var jsonExpr, dateExpr string
	if d.Driver == "sqlite" {
		jsonExpr = `json_extract(payload_json, '$.force_reason')`
		dateExpr = `date_created >= datetime('now', '-30 days')`
	} else {
		jsonExpr = `JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.force_reason'))`
		dateExpr = `date_created >= DATE_SUB(NOW(), INTERVAL 30 DAY)`
	}
	ctx, cancel := context.WithTimeout(ctx, communityHitsBudget)
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
