// Package rulehits counts the requests each custom rule decided, by the hour,
// for the settings tab's "last 24 hours" figure and the time a rule last
// fired.  In memory: a restart starts the count over, which the tab says.
package rulehits

import (
	"sync"
	"time"
)

// Hours is the window kept.
const Hours = 24

type hour struct {
	at int64 // the unix hour this slot holds
	n  map[string]uint32
}

// Counter is the ring; a nil *Counter is safe to call.
type Counter struct {
	mu    sync.Mutex
	hours [Hours]hour
	last  map[string]int64 // unix second a rule last fired
	since int64            // unix second the counter started
}

func New() *Counter { return &Counter{last: map[string]int64{}, since: time.Now().Unix()} }

// Hit records one request the rule id decided.
func (c *Counter) Hit(id string, now time.Time) {
	if c == nil || id == "" {
		return
	}
	h := now.Unix() / 3600
	c.mu.Lock()
	s := &c.hours[h%Hours]
	if s.at != h {
		*s = hour{at: h, n: map[string]uint32{}}
	}
	s.n[id]++
	if at := now.Unix(); at > c.last[id] {
		c.last[id] = at
	}
	c.mu.Unlock()
}

// Stat is one rule's figures.
type Stat struct {
	Day  uint32 // requests in the last Hours hours
	Last int64  // unix second it last fired, 0 if never since the start
}

// Snapshot reads every rule's figures as of now, plus when counting began.
func (c *Counter) Snapshot(now time.Time) (map[string]Stat, int64) {
	out := map[string]Stat{}
	if c == nil {
		return out, 0
	}
	cur := now.Unix() / 3600
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.hours {
		s := &c.hours[i]
		if s.at == 0 || cur-s.at >= Hours {
			continue
		}
		for id, n := range s.n {
			st := out[id]
			st.Day += n
			out[id] = st
		}
	}
	for id, at := range c.last {
		st := out[id]
		st.Last = at
		out[id] = st
	}
	return out, c.since
}
