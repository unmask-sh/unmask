// Package live keeps the last five minutes of request outcomes in memory, one
// second at a time, for the dashboard's "right now" strip.
//
// Every other counter the daemon keeps is a minute at its finest and reaches
// the database a minute or two after the fact (nginxlog's buckets, the hourly
// rollups).  That is the right shape for a chart of the day and the wrong one
// for a strip that says what is arriving now: by the time a minute bucket can
// be read, the moment it describes is over.  So this is a ring of seconds that
// is never written to disk and never read by SQL.  The access-log reader and
// the event writer add to it; the dashboard's JSON endpoint takes a snapshot.
//
// It is deliberately small: seven counters a second for Span seconds, and per
// second a map of the source countries seen (the map on the dashboard draws
// from those).  Nothing is allocated on the hot path beyond that map's entries,
// and a slot is reused in place once its second has passed out of the ring.
package live

import (
	"sync"
	"time"
)

// Kind is one outcome a request can be counted under.  A request counts as
// Requests always, and under as many of the others as apply.
type Kind uint8

const (
	Requests  Kind = iota // every access-log line (or forward-auth check)
	Pass                  // admitted on a valid pass cookie (pow / captcha / rebind)
	Bypass                // let through unjudged: a bypass rule, or a listed crawler
	Serve                 // a challenge page was the answer
	Solve                 // a challenge was cleared: a bv_* cookie was issued
	Deny                  // refused: a honeypot trip, or a banned client whose action is deny
	RateLimit             // the rate-limit path fired (its CAPTCHA or deny, with 429)
	NumKinds
)

// Names spells the kinds the way the JSON endpoint does, in Kind order.
var Names = [NumKinds]string{"requests", "pass", "bypass", "serve", "solve", "deny", "rate_limit"}

// Mask is the set of kinds one request counts under.
type Mask uint16

// Of builds a Mask from kinds.
func Of(kinds ...Kind) Mask {
	var m Mask
	for _, k := range kinds {
		m |= 1 << k
	}
	return m
}

// Has reports whether k is in m.
func (m Mask) Has(k Kind) bool { return m&(1<<k) != 0 }

const (
	// Span is how many seconds the ring holds.
	Span = 300
	// Step is the width, in seconds, of one bucket of a snapshot's series.
	Step = 5
	// Window is how many seconds the headline figures and the countries cover.
	Window   = 60
	nBuckets = Span / Step
)

// slot is one second of the ring.  sec says which second it holds; a slot
// whose sec is not the one being read is stale and reads as empty.
type slot struct {
	sec int64
	n   [NumKinds]uint32
	cc  map[string]*[NumKinds]uint32
}

// Minutes is the number of one-minute buckets kept beside the second ring:
// the realtime page's window, thirty minutes drawn a minute at a time.
const Minutes = 30

// minSlot is one minute of the longer ring: the counts and the per-country
// counts of every hit whose unix minute is min (0 = never used).
type minSlot struct {
	min int64
	n   [NumKinds]uint32
	cc  map[string]*[NumKinds]uint32
}

// Counter is the ring.  The zero value is not ready; use New.
type Counter struct {
	mu    sync.Mutex
	slots [Span]slot
	mins  [Minutes]minSlot
	// lastLine is the unix second of the most recent Requests hit: whether the
	// feed that fills the strip is alive at all.
	lastLine int64
}

// New returns an empty Counter.
func New() *Counter { return &Counter{} }

// Hit records one request at now, from country cc ("" = unknown), under every
// kind in m.  nil-safe.
func (c *Counter) Hit(now time.Time, cc string, m Mask) {
	if c == nil || m == 0 {
		return
	}
	sec := now.Unix()
	c.mu.Lock()
	s := &c.slots[sec%Span]
	if s.sec != sec {
		// The slot held a second that has passed out of the ring: start over.
		// Dropping the map (rather than clearing it) is what frees its entries.
		*s = slot{sec: sec}
	}
	var e *[NumKinds]uint32
	if cc != "" {
		if s.cc == nil {
			s.cc = map[string]*[NumKinds]uint32{}
		}
		if e = s.cc[cc]; e == nil {
			e = new([NumKinds]uint32)
			s.cc[cc] = e
		}
	}
	// The minute ring, kept the same way.
	mn := sec / 60
	ms := &c.mins[mn%Minutes]
	if ms.min != mn {
		*ms = minSlot{min: mn}
	}
	var me *[NumKinds]uint32
	if cc != "" {
		if ms.cc == nil {
			ms.cc = map[string]*[NumKinds]uint32{}
		}
		if me = ms.cc[cc]; me == nil {
			me = new([NumKinds]uint32)
			ms.cc[cc] = me
		}
	}
	for k := Kind(0); k < NumKinds; k++ {
		if !m.Has(k) {
			continue
		}
		s.n[k]++
		ms.n[k]++
		if e != nil {
			e[k]++
		}
		if me != nil {
			me[k]++
		}
	}
	if m.Has(Requests) && sec > c.lastLine {
		c.lastLine = sec
	}
	c.mu.Unlock()
}

// Solved phases: a challenge cleared and its bv_* cookie issued, named after
// the chain that issued it.
var solvedPhases = map[string]bool{"bv_pow_only": true, "bv_captcha_only": true, "bv_pow_then_captcha": true}

// ObserveEvent counts what the event log says that the access log cannot: a
// solved challenge, and a serve on the rate-limit path.  Every event passes
// through here; the ones that say neither cost a map lookup.
func (c *Counter) ObserveEvent(now time.Time, phase, cc string, rateLimited bool) {
	if c == nil {
		return
	}
	switch {
	case solvedPhases[phase]:
		c.Hit(now, cc, Of(Solve))
	case phase == "serve" && rateLimited:
		c.Hit(now, cc, Of(RateLimit))
	}
}

// Country is one source country's share of the last Window seconds.
type Country struct {
	N      uint32 `json:"n"`
	Pass   uint32 `json:"pass"`
	Bypass uint32 `json:"bypass"`
	Serve  uint32 `json:"serve"`
	Deny   uint32 `json:"deny"`
}

// Snapshot is one reading of the ring, ending at the second it was taken.
type Snapshot struct {
	// At is the unix second the reading ends at (exclusive): the second after
	// the one it was taken in.
	At int64
	// Series holds Span/Step buckets per kind, oldest first, each the sum of
	// Step seconds; the last bucket is the most recent Step seconds.
	Series [NumKinds][nBuckets]uint32
	// Last covers the Window seconds up to At; Prev the Window before that.
	Last, Prev [NumKinds]uint32
	// Requests per second: over the last Step seconds, the busiest Step bucket
	// of the Span, and the Span's mean.
	TPS, Peak, Avg float64
	// Countries is the last Window seconds by source country ("" is not a key:
	// requests of unknown country count only in the totals).
	Countries map[string]Country
	// PerMinute holds the last Minutes minutes per kind, oldest first; the
	// last entry is the minute the reading was taken in, still filling.
	PerMinute [NumKinds][Minutes]uint32
	// Last30 is the sum of PerMinute; Countries30 the same minutes by source
	// country.
	Last30      [NumKinds]uint32
	Countries30 map[string]Country
	// LastLine is the unix second of the most recent request counted, 0 if
	// none ever was.
	LastLine int64
}

// Snapshot reads the ring as of now.  nil-safe: a nil Counter reads as empty.
func (c *Counter) Snapshot(now time.Time) Snapshot {
	end := now.Unix() + 1
	start := end - Span
	sn := Snapshot{At: end, Countries: map[string]Country{}, Countries30: map[string]Country{}}
	if c == nil {
		return sn
	}
	c.mu.Lock()
	sn.LastLine = c.lastLine
	curMin := (end - 1) / 60
	for i := 0; i < Minutes; i++ {
		mn := curMin - int64(Minutes-1) + int64(i)
		if mn < 0 {
			continue
		}
		ms := &c.mins[mn%Minutes]
		if ms.min != mn {
			continue
		}
		for k := Kind(0); k < NumKinds; k++ {
			sn.PerMinute[k][i] = ms.n[k]
			sn.Last30[k] += ms.n[k]
		}
		for cc, e := range ms.cc {
			x := sn.Countries30[cc]
			x.N += e[Requests]
			x.Pass += e[Pass]
			x.Bypass += e[Bypass]
			x.Serve += e[Serve]
			x.Deny += e[Deny]
			sn.Countries30[cc] = x
		}
	}
	for sec := start; sec < end; sec++ {
		s := &c.slots[sec%Span]
		if s.sec != sec {
			continue
		}
		b := int(sec-start) / Step
		age := end - 1 - sec // 0 for the second the reading is taken in
		for k := Kind(0); k < NumKinds; k++ {
			sn.Series[k][b] += s.n[k]
			switch {
			case age < Window:
				sn.Last[k] += s.n[k]
			case age < 2*Window:
				sn.Prev[k] += s.n[k]
			}
		}
		if age < Window {
			for cc, e := range s.cc {
				x := sn.Countries[cc]
				x.N += e[Requests]
				x.Pass += e[Pass]
				x.Bypass += e[Bypass]
				x.Serve += e[Serve]
				x.Deny += e[Deny]
				sn.Countries[cc] = x
			}
		}
	}
	c.mu.Unlock()
	var total, peak uint32
	for _, v := range sn.Series[Requests] {
		total += v
		if v > peak {
			peak = v
		}
	}
	sn.TPS = float64(sn.Series[Requests][nBuckets-1]) / Step
	sn.Peak = float64(peak) / Step
	sn.Avg = float64(total) / Span
	return sn
}

// Buckets is the number of buckets in a snapshot's series.
const Buckets = nBuckets
