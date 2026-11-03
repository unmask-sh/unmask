package handlers

import (
	"sync"
	"time"
)

// scoreStash keeps the CAPTCHA score each /verify computed, by the page's
// beacon token, for the beacon that reports the outcome.
//
// The verify answer used to carry the score, and the page echoed it on its
// verify_ng / bv_* beacon, which is where the hunt and the CAPTCHA failure
// ranking read it.  Saying the number back is an oracle: a script shaping a
// fabricated signal learns from each answer how close it is.  The page has no
// use for it, so the answer stops carrying it and the daemon writes what it
// computed on the beacon itself (DebugBeacon), which also makes the recorded
// score the daemon's rather than the page's word.
//
// In this process only: behind a balancer the beacon may reach another node
// than the verify did, and that beacon records no score -- the same bound the
// single-use proof-of-load token already lives with.  Entries live as long as
// a beacon token does and are swept as the stash is used; past scoreStashMax
// the stash starts over rather than grow.
type scoreStash struct {
	mu sync.Mutex
	m  map[string]scoreEntry
}

type scoreEntry struct {
	score float64
	at    time.Time
}

const scoreStashMax = 100000

// put remembers score for bt; a bt that is not a beacon token is not kept
// (the beacon it would be read on would be refused anyway).
func (s *scoreStash) put(bt string, score float64, now time.Time) {
	if bt == "" || len(bt) > 200 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil || len(s.m) >= scoreStashMax {
		s.m = map[string]scoreEntry{}
	}
	if len(s.m)%256 == 0 {
		for k, e := range s.m {
			if now.Sub(e.at) > beaconTokenTTL {
				delete(s.m, k)
			}
		}
	}
	s.m[bt] = scoreEntry{score: score, at: now}
}

// get is the score put for bt, if one was and it is not older than a beacon
// token lives.
func (s *scoreStash) get(bt string, now time.Time) (float64, bool) {
	if bt == "" {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[bt]
	if !ok || now.Sub(e.at) > beaconTokenTTL {
		return 0, false
	}
	return e.score, true
}

// isCaptchaOutcomePhase: the beacons that report how a CAPTCHA verify went --
// a refusal, or the pass of a chain that ends in a CAPTCHA -- the ones the
// score belongs on.
func isCaptchaOutcomePhase(phase string) bool {
	switch phase {
	case "verify_ng", "bv_captcha_only", "bv_pow_then_captcha":
		return true
	}
	return false
}
