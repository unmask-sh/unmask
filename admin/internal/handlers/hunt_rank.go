package handlers

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
)

// The hunt page's ranking tables: IP / JA4 / UA / network, over the tab's
// window, filters not applied.
//
// They are aggregate scans over the event table.  Run one after another on a
// shared budget, the first slow one starved the rest: on an 8M-row database
// the JA4 scan alone took the whole 10 s, and the UA and network tables came
// back "could not be read" on every load (a four-month log of one such
// install: 68 failures, 26 of them the network table, which ran last).  Each
// ranking now has its own budget, so a slow table costs only itself.
//
// Still one after another, deliberately.  Side by side they finished barely
// sooner in total (16.8 s -> 13.9 s for a day's window on the pure-Go SQLite
// driver, which scales poorly across connections) while each took twice as
// long and every one of them overran its budget -- three empty tables instead
// of one.  The page's own cap bounds the serial worst case.
//
// And they were recomputed for every page.  The rankings ignore the row
// filters and the offset, so page 2 of a paging session computed exactly the
// tables page 1 had just shown -- the same four scans, warm this time, which
// is why the second page felt "better" rather than fast.  A page-1 load now
// keeps its tables for the pages that follow it, matched by the freeze id
// those pages carry (events.WithHuntFreeze): a fresh page 1 pins a new id and
// computes afresh, so a reload still shows the live ranking.

// rankQueryTimeout bounds each ranking separately.  A variable so the
// unavailable-ranking test can make them fail without a slow database.
var rankQueryTimeout = 10 * time.Second

// rankPageBudget bounds the rankings as a whole: a table not yet started when
// the page has spent this much on the others is skipped and reported like a
// table that timed out.  Three tables of a day's window take ~17 s warm on
// the 8M-row reference database, so this lets a healthy page finish while a
// page on a cold disk cannot run past the sum of four budgets.
var rankPageBudget = 30 * time.Second

// huntRankSet is one computation of the four tables.  failed names the
// tables that could not be read; absent means not attempted (the network
// table needs the ASN database).
type huntRankSet struct {
	ip, ja4, ua []events.RankRow
	asn         []events.ASNRankRow
	failed      map[string]bool
}

func (s huntRankSet) anyFailed() bool {
	for _, f := range s.failed {
		if f {
			return true
		}
	}
	return false
}

// runHuntRankings computes the tables one after another, each under its own
// rankQueryTimeout and all under rankPageBudget.  wantASN says whether the
// network table can be resolved (an ASN database is loaded).
func (h *Handler) runHuntRankings(ctx context.Context, sinceMin int, wantASN bool) huntRankSet {
	set := huntRankSet{failed: map[string]bool{}}
	started := time.Now()
	run := func(name string, fn func(c context.Context) error) {
		if time.Since(started) > rankPageBudget {
			log.Printf("unmask: hunt %s ranking skipped: the page spent its %v on the rankings before it", name, rankPageBudget)
			set.failed[name] = true
			return
		}
		c, cancel := context.WithTimeout(ctx, rankQueryTimeout)
		defer cancel()
		err := fn(c)
		logRankErr(name, err)
		set.failed[name] = err != nil
	}
	run("ip", func(c context.Context) error {
		rows, err := events.RankByIP(c, h.DB, sinceMin, 30, "")
		set.ip = rows
		return err
	})
	run("ja4", func(c context.Context) error {
		rows, err := events.RankByJA4(c, h.DB, sinceMin, 30, "")
		set.ja4 = rows
		return err
	})
	run("ua", func(c context.Context) error {
		rows, err := events.RankByUA(c, h.DB, sinceMin, 30, "")
		set.ua = rows
		return err
	})
	if wantASN {
		run("asn", func(c context.Context) error {
			// LookupASN, not LookupInfo: this walks every distinct IP in the
			// window once, where LookupInfo's country lookup is wasted work and
			// its cache is pure overhead (see ipgeo.LookupASN).
			rows, err := events.RankByASN(c, h.DB, sinceMin, 30, h.IPGeo.LookupASN)
			set.asn = rows
			return err
		})
	}
	return set
}

// huntRankKey identifies the window a set of tables was computed for, plus
// the freeze id of the paging session that will reuse it.
func huntRankKey(rng string, sinceMin int, customFrom, customTo, freezeID int64) string {
	return fmt.Sprintf("%s|%d|%d|%d|%d", rng, sinceMin, customFrom, customTo, freezeID)
}

const (
	huntRankTTL = 10 * time.Minute // a paging session older than this recomputes
	huntRankMax = 16               // sets kept; each is four tables of <= 30 rows
)

// huntRankCache holds the tables of recent page-1 loads.  Only complete sets
// are kept: a set with a table that timed out is recomputed by the next page,
// which may have better luck.
type huntRankCache struct {
	mu      sync.Mutex
	entries map[string]huntRankEntry
}

type huntRankEntry struct {
	set huntRankSet
	at  time.Time
}

func (c *huntRankCache) get(key string) (huntRankSet, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Since(e.at) > huntRankTTL {
		return huntRankSet{}, false
	}
	return e.set, true
}

func (c *huntRankCache) put(key string, set huntRankSet) {
	if set.anyFailed() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]huntRankEntry{}
	}
	now := time.Now()
	for k, e := range c.entries { // expired entries go first
		if now.Sub(e.at) > huntRankTTL {
			delete(c.entries, k)
		}
	}
	for len(c.entries) >= huntRankMax { // then the oldest
		oldestK, oldest := "", now
		for k, e := range c.entries {
			if e.at.Before(oldest) {
				oldestK, oldest = k, e.at
			}
		}
		delete(c.entries, oldestK)
	}
	c.entries[key] = huntRankEntry{set: set, at: now}
}
