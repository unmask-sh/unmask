// cache.go — the candidate list, served from memory and refreshed behind
// the page.
//
// The engine reads every event of the window (a day is fifty thousand rows on
// a busy install, a week four hundred thousand) and the first read after a
// while comes off the disk: two to six seconds for the page, and again for
// the click that asks the model, and again for the swap that follows it.
// The list does not change at that pace.  So the raw list -- before the
// operator's exclusions, a few times the page's limit -- is kept per window
// and served at once; when it is older than cacheFresh a refresh runs in the
// background and the next reader gets the new one; only a list older than
// cacheMax (or none at all) makes a reader wait.  Exclusions (bans,
// dismissals, monitoring) are applied on the way out, so a dismiss takes
// effect immediately without a recompute.
package advisor

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
)

const (
	cacheFresh = 60 * time.Second // older than this: serve it, refresh behind
	cacheMax   = 15 * time.Minute // older than this: recompute before serving
	rawFactor  = 3                // raw list = rawFactor x the page's limit, so exclusions leave enough
)

type cacheEntry struct {
	at         time.Time
	cands      []Candidate
	refreshing bool
}

var candCache = struct {
	sync.Mutex
	m map[string]*cacheEntry
}{m: map[string]*cacheEntry{}}

func cacheKey(conn *db.DB, opt Options) string {
	// The connection is part of the key: one process can serve more than one
	// database (tests do), and the list is per database.
	return fmt.Sprintf("%p|w%d|%d|%d|%d|%d|%d", conn, opt.WindowMinutes, opt.MinServes, opt.MinScanner, opt.MinPasses, opt.HerdMinIPs, opt.Limit)
}

func rawOptions(opt Options) Options {
	raw := opt
	raw.Limit = opt.Limit * rawFactor
	return raw
}

// CachedCandidates is Candidates with the cache in front: the list for the
// window, exclusions applied, and when it was computed.
func CachedCandidates(ctx context.Context, conn *db.DB, gip *ipgeo.Reader, excl Exclusions, opt Options) ([]Candidate, time.Time, error) {
	opt = opt.resolved()
	key := cacheKey(conn, opt)
	now := time.Now()

	candCache.Lock()
	e := candCache.m[key]
	if e != nil && now.Sub(e.at) < cacheMax {
		if now.Sub(e.at) >= cacheFresh && !e.refreshing {
			e.refreshing = true
			go refreshCandidates(key, conn, gip, opt)
		}
		cands, at := applyExclusions(e.cands, excl, opt.Limit), e.at
		candCache.Unlock()
		return cands, at, nil
	}
	candCache.Unlock()

	raw, err := Candidates(ctx, conn, gip, Exclusions{}, rawOptions(opt))
	if err != nil {
		return nil, time.Time{}, err
	}
	at := time.Now()
	candCache.Lock()
	candCache.m[key] = &cacheEntry{at: at, cands: raw}
	candCache.Unlock()
	return applyExclusions(raw, excl, opt.Limit), at, nil
}

func refreshCandidates(key string, conn *db.DB, gip *ipgeo.Reader, opt Options) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	raw, err := Candidates(ctx, conn, gip, Exclusions{}, rawOptions(opt))
	candCache.Lock()
	defer candCache.Unlock()
	e := candCache.m[key]
	if err != nil {
		log.Printf("advisor: background refresh: %v", err)
		if e != nil {
			e.refreshing = false
		}
		return
	}
	candCache.m[key] = &cacheEntry{at: time.Now(), cands: raw}
}

// applyExclusions drops what the operator does not want proposed (Candidates
// does the same inside its scan when called directly) and cuts to the limit.
// Private and loopback addresses never made it into the raw list.
func applyExclusions(raw []Candidate, excl Exclusions, limit int) []Candidate {
	out := make([]Candidate, 0, len(raw))
	for _, c := range raw {
		switch c.Type {
		case "ip":
			if excl.BannedIPs[c.Target] || excl.DismissedIP[c.Target] || excl.ExcludeIPs[c.Target] {
				continue
			}
		case "ja4":
			if excl.BannedJA4s[c.Target] || excl.DismissedJA4[c.Target] {
				continue
			}
		}
		out = append(out, c)
		if len(out) == limit {
			break
		}
	}
	return out
}

// ResetCandidateCache forgets every cached list.  Tests use it between
// seeds; a restart does the same for real.
func ResetCandidateCache() {
	candCache.Lock()
	candCache.m = map[string]*cacheEntry{}
	candCache.Unlock()
}
