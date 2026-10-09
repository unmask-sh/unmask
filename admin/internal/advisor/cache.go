package advisor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
)

// The candidate list is computed off the request.
//
// Extracting candidates is a pass over every event in the window -- two
// aggregates by address and by fingerprint with a dozen conditional sums
// each.  On an 8M-row database a day's window took 26 s + 17 s warm, and the
// page that waited for it ran into the server's write timeout and answered
// nothing.  So a request never computes: it shows the list it has (saying
// how old it is, refreshing behind once it is older than cacheFresh), and
// when there is none yet it starts the computation, waits computeWait for a
// small database to finish, and otherwise renders "being computed" -- the
// page polls and reloads when the list lands.
const (
	cacheFresh = 60 * time.Second // older than this: serve it, refresh behind
	cacheKeep  = 24 * time.Hour   // older than this: not shown; a fresh one is computed first
	rawFactor  = 3                // raw list = rawFactor x the page's limit, so exclusions leave enough
	// computeBudget bounds one computation.  Generous: a slow disk under a
	// day's window is exactly the case this exists for, and nothing waits on it.
	computeBudget = 10 * time.Minute
)

// computeWait is how long a request that had to start the computation waits
// for it before answering "being computed".  A var so a test can make the
// asynchronous path happen on a database that would answer at once.
var computeWait = 2 * time.Second

// ErrComputing says there is no list yet and one is being computed.
var ErrComputing = errors.New("advisor: candidates are being computed")

type cacheEntry struct {
	at         time.Time
	cands      []Candidate
	refreshing bool
	started    time.Time     // when the running computation began
	done       chan struct{} // closed when it ends, success or not
	lastErr    error         // the last computation's failure; cleared by a success
}

var candCache = struct {
	sync.Mutex
	m map[string]*cacheEntry
}{m: map[string]*cacheEntry{}}

func cacheKey(conn *db.DB, opt Options) string {
	return fmt.Sprintf("%p|w%d|%d|%d|%d|%d|%d", conn, opt.WindowMinutes, opt.MinServes, opt.MinScanner, opt.MinPasses, opt.HerdMinIPs, opt.Limit)
}

func rawOptions(opt Options) Options {
	raw := opt
	raw.Limit = opt.Limit * rawFactor
	return raw
}

// CachedCandidates returns the window's list and when it was computed.  A
// list older than cacheFresh is returned as is and refreshed behind.  With
// no list to show it returns ErrComputing (a computation is running; see
// CandidateStatus), or the computation's error when it failed.
func CachedCandidates(ctx context.Context, conn *db.DB, gip *ipgeo.Reader, excl Exclusions, opt Options) ([]Candidate, time.Time, error) {
	opt = opt.resolved()
	key := cacheKey(conn, opt)
	now := time.Now()
	candCache.Lock()
	e := candCache.m[key]
	if e == nil {
		e = &cacheEntry{}
		candCache.m[key] = e
	}
	have := !e.at.IsZero() && now.Sub(e.at) < cacheKeep
	if have {
		if now.Sub(e.at) >= cacheFresh && !e.refreshing {
			startCompute(e, conn, gip, opt)
		}
		cands, at := applyExclusions(e.cands, excl, opt.Limit), e.at
		candCache.Unlock()
		return cands, at, nil
	}
	if !e.refreshing {
		startCompute(e, conn, gip, opt)
	}
	done := e.done
	candCache.Unlock()

	select {
	case <-done:
	case <-time.After(computeWait):
	case <-ctx.Done():
		return nil, time.Time{}, ctx.Err()
	}
	candCache.Lock()
	defer candCache.Unlock()
	if !e.at.IsZero() {
		return applyExclusions(e.cands, excl, opt.Limit), e.at, nil
	}
	if e.lastErr != nil && !e.refreshing {
		return nil, time.Time{}, e.lastErr
	}
	return nil, time.Time{}, ErrComputing
}

// startCompute runs the engine for the entry on its own goroutine.  The
// caller holds candCache.
func startCompute(e *cacheEntry, conn *db.DB, gip *ipgeo.Reader, opt Options) {
	e.refreshing = true
	e.started = time.Now()
	done := make(chan struct{})
	e.done = done
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), computeBudget)
		defer cancel()
		raw, err := Candidates(ctx, conn, gip, Exclusions{}, rawOptions(opt))
		candCache.Lock()
		defer candCache.Unlock()
		e.refreshing = false
		close(done)
		if err != nil {
			log.Printf("advisor: candidates (window %dm): %v after %v", opt.WindowMinutes, err, time.Since(e.started).Round(time.Second))
			e.lastErr = err
			return
		}
		e.lastErr = nil
		e.at = time.Now()
		e.cands = raw
	}()
}

// Status is the state of one window's list, for the page while it waits.
type Status struct {
	Computing bool      // a computation is running
	Since     time.Time // when it started
	At        time.Time // when the list on hand was computed; zero for none
	Err       string    // the last computation's failure, "" when it succeeded
}

// CandidateStatus reports the window's list without touching it.
func CandidateStatus(conn *db.DB, opt Options) Status {
	opt = opt.resolved()
	candCache.Lock()
	defer candCache.Unlock()
	e := candCache.m[cacheKey(conn, opt)]
	if e == nil {
		return Status{}
	}
	st := Status{Computing: e.refreshing, Since: e.started, At: e.at}
	if e.lastErr != nil {
		st.Err = e.lastErr.Error()
	}
	return st
}

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

// SetComputeWaitForTest makes a request answer "being computed" before the
// engine has finished, on a database that would otherwise answer at once.
// Returns the restore function.
func SetComputeWaitForTest(d time.Duration) func() {
	orig := computeWait
	computeWait = d
	return func() { computeWait = orig }
}
