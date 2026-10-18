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
// It is deliberately small: eight counters a second for Span seconds, and per
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
	Bypass                // let through unjudged: a bypass rule, an unprotected location, monitor mode
	Serve                 // a challenge page was the answer (its serve event)
	Solve                 // a challenge was cleared: a bv_* cookie was issued
	Deny                  // refused with a deny page, for any reason (its serve event, deny=1)
	RateLimit             // the rate-limit path fired (its CAPTCHA or deny, with 429)
	// Abandon: an ordinary visitor's proof-of-work left unfinished -- the page
	// loaded, no rule had sent them there, and they went away.  Taken out of
	// the challenged requests the way the dashboard's blocked count takes it
	// out: someone who walked away was not stopped.
	Abandon
	// Crawler: a listed crawler this configuration let through on purpose
	// (named in the crawler list, and past the IP-range check where that is
	// on).  Judged and admitted, not bypassed: the dashboard's benign bots,
	// so the judged requests keep it while the bypassed ones leave.
	Crawler
	NumKinds
)

// Names spells the kinds the way the JSON endpoint does, in Kind order.
var Names = [NumKinds]string{"requests", "pass", "bypass", "serve", "solve", "deny", "rate_limit", "abandon", "crawler"}

// BlockedName is the JSON key of the one figure a reading derives rather than
// counts (Snapshot.Blocked).  Not a Kind: no request is ever counted under it.
const BlockedName = "blocked"

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
// counts of every hit whose unix minute is min (0 = never used), and the
// requests refused outright in that minute, by reason and by matching rule.
type minSlot struct {
	min     int64
	n       [NumKinds]uint32
	cc      map[string]*[NumKinds]uint32
	refused map[string]uint32
	rules   map[string]map[string]uint32
}

// maxRules bounds the rules one reason keeps per minute.  The rules are the
// operator's own (AS numbers, countries, custom rules), so this is a guard
// against a configuration far larger than any seen, not a sampling choice.
const maxRules = 256

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
// solved challenge, what the daemon answered a gated request with -- a
// challenge page or a deny page, on the rate-limit path or not -- an ordinary
// visitor's abandoned proof-of-work, and the reason and rule behind a deny
// page.  p is the event's payload.  Every event passes through here; the ones
// that say none of it cost a map lookup.
//
// The access log cannot tell the two answers apart: an ASN, country or custom
// rule's deny and a challenge are both a request a gate handed to the daemon.
// Counting them there put every refusal but a ban's under the challenges, and
// left the deny tile with the bans alone.
func (c *Counter) ObserveEvent(now time.Time, phase, cc string, p map[string]any) {
	if c == nil {
		return
	}
	switch {
	case solvedPhases[phase]:
		c.Hit(now, cc, Of(Solve))
	case phase == "serve":
		m := Of(Serve)
		if flag(p, "deny") {
			m = Of(Deny)
		}
		if flag(p, "rl") {
			m |= Of(RateLimit)
		}
		c.Hit(now, cc, m)
	case phase == "abandon" && unruledPoW(p):
		c.Hit(now, cc, Of(Abandon))
	}
	if flag(p, "deny") {
		reason, _ := p["force_reason"].(string)
		rule, _ := p["deny_rule"].(string)
		if reason == "" {
			reason = "axis_deny"
		}
		c.Refuse(now, reason, rule)
	}
}

// flag reads a payload marker the serve paths write as the number 1 (and
// anything that went through JSON as 1.0 or "1").
func flag(p map[string]any, key string) bool {
	switch v := p[key].(type) {
	case int:
		return v == 1
	case int64:
		return v == 1
	case float64:
		return v == 1
	case bool:
		return v
	case string:
		return v == "1"
	}
	return false
}

// unruledPoW: the challenge was the transparent proof-of-work and no rule had
// sent the visitor to it -- the same narrowing the dashboard's abandon figure
// makes, so a CAPTCHA a targeted client never solves stays counted as stopped.
func unruledPoW(p map[string]any) bool {
	reason, _ := p["force_reason"].(string)
	mode, _ := p["chmode"].(string)
	return (reason == "" || reason == "none") && mode == "pow_only"
}

// Refuse records one request unmask refused outright -- a deny page, not a
// challenge -- under the reason it was refused for and, where the reason has
// one, the rule that matched (an AS number, a country code).  Minute
// resolution only: it feeds the thirty-minute breakdown.  nil-safe.
func (c *Counter) Refuse(now time.Time, reason, rule string) {
	if c == nil || reason == "" {
		return
	}
	mn := now.Unix() / 60
	c.mu.Lock()
	defer c.mu.Unlock()
	ms := &c.mins[mn%Minutes]
	if ms.min != mn {
		*ms = minSlot{min: mn}
	}
	if ms.refused == nil {
		ms.refused = map[string]uint32{}
	}
	ms.refused[reason]++
	if rule == "" {
		return
	}
	if ms.rules == nil {
		ms.rules = map[string]map[string]uint32{}
	}
	r := ms.rules[reason]
	if r == nil {
		r = map[string]uint32{}
		ms.rules[reason] = r
	}
	if _, seen := r[rule]; seen || len(r) < maxRules {
		r[rule]++
	}
}

// Country is one source country's share of the last Window seconds.
type Country struct {
	N       uint32 `json:"n"`
	Pass    uint32 `json:"pass"`
	Bypass  uint32 `json:"bypass"`
	Serve   uint32 `json:"serve"`
	Deny    uint32 `json:"deny"`
	Solve   uint32 `json:"solve"`
	Abandon uint32 `json:"abandon"`
	Crawler uint32 `json:"crawler"`
	// Blocked and People split the requests that met a challenge or a deny.
	// Blocked is what nobody cleared: the dashboard's "bot accesses unmask
	// blocked" (challenges fired, minus PoW/CAPTCHA solves, minus visitors who
	// walked away) for one country.  People is the rest: the challenges a
	// person cleared or walked away from.  The parts come from two logs (the
	// access log, the event log), so People is capped at what met a challenge.
	Blocked uint32 `json:"blocked"`
	People  uint32 `json:"people"`
}

func (x *Country) add(e *[NumKinds]uint32) {
	x.N += e[Requests]
	x.Pass += e[Pass]
	x.Bypass += e[Bypass]
	x.Serve += e[Serve]
	x.Deny += e[Deny]
	x.Solve += e[Solve]
	x.Abandon += e[Abandon]
	x.Crawler += e[Crawler]
}

func (x *Country) settle() {
	x.Blocked, x.People = split(x.Serve+x.Deny, x.Solve+x.Abandon)
}

// split divides what met a challenge or a deny page (met) into the blocked
// bots and the people, given what a person cleared or walked away from (out).
// The dashboard's headline, "bot requests blocked by unmask", is the same
// difference over a day; the map's countries and the strip's blocked tile both
// take it from here, so the three cannot drift apart.  The parts come from two
// logs (the access log, the event log), so out is capped at met: the people
// never outnumber what met a challenge, and blocked never goes below zero.
func split(met, out uint32) (blocked, people uint32) {
	if out > met {
		out = met
	}
	return met - out, out
}

// blockedOf is split's blocked side for one set of counts.
func blockedOf(serve, deny, solve, abandon uint32) uint32 {
	b, _ := split(serve+deny, solve+abandon)
	return b
}

// Derived is a figure a Snapshot computes from its kinds, shaped like one
// kind's counters.  The window figures are each window's own difference, not
// the sum of its minutes' or buckets': a solve lands seconds after its
// challenge, so at a minute's edge the two fall into different minutes, and a
// sum of minutes clamped at zero would count that challenge as blocked.  The
// per-minute and per-bucket values are each span's own difference: the shape
// of the half hour, not a ledger that adds up to the headline.
type Derived struct {
	// Last covers the Window seconds up to At, Prev the Window before that,
	// Last30 the Minutes minutes.
	Last, Prev, Last30 uint32
	PerMinute          [Minutes]uint32
	Series             [nBuckets]uint32
}

func settleAll(m map[string]Country) {
	for cc, x := range m {
		x.settle()
		m[cc] = x
	}
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
	// Refused30 is the requests refused outright in the same minutes, by
	// reason; Rules30 the same by reason and matching rule.
	Refused30 map[string]uint32
	Rules30   map[string]map[string]uint32
	// LastLine is the unix second of the most recent request counted, 0 if
	// none ever was.
	LastLine int64
	// Blocked is the dashboard's "bot requests blocked by unmask" over this
	// reading: what met a challenge or a deny page (Serve + Deny), less what a
	// person cleared or walked away from (Solve + Abandon), over the same
	// windows and series as a kind's.  The strip's blocked tile; the total of
	// what the map draws by default (Country.Blocked, a country at a time).
	Blocked Derived
}

// Snapshot reads the ring as of now.  nil-safe: a nil Counter reads as empty.
func (c *Counter) Snapshot(now time.Time) Snapshot {
	end := now.Unix() + 1
	start := end - Span
	sn := Snapshot{At: end, Countries: map[string]Country{}, Countries30: map[string]Country{},
		Refused30: map[string]uint32{}, Rules30: map[string]map[string]uint32{}}
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
			x.add(e)
			sn.Countries30[cc] = x
		}
		for reason, n := range ms.refused {
			sn.Refused30[reason] += n
		}
		for reason, rs := range ms.rules {
			r := sn.Rules30[reason]
			if r == nil {
				r = map[string]uint32{}
				sn.Rules30[reason] = r
			}
			for rule, n := range rs {
				r[rule] += n
			}
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
				x.add(e)
				sn.Countries[cc] = x
			}
		}
	}
	c.mu.Unlock()
	settleAll(sn.Countries)
	settleAll(sn.Countries30)
	sn.Blocked = Derived{
		Last:   blockedOf(sn.Last[Serve], sn.Last[Deny], sn.Last[Solve], sn.Last[Abandon]),
		Prev:   blockedOf(sn.Prev[Serve], sn.Prev[Deny], sn.Prev[Solve], sn.Prev[Abandon]),
		Last30: blockedOf(sn.Last30[Serve], sn.Last30[Deny], sn.Last30[Solve], sn.Last30[Abandon]),
	}
	for i := range sn.Blocked.PerMinute {
		sn.Blocked.PerMinute[i] = blockedOf(sn.PerMinute[Serve][i], sn.PerMinute[Deny][i], sn.PerMinute[Solve][i], sn.PerMinute[Abandon][i])
	}
	for i := range sn.Blocked.Series {
		sn.Blocked.Series[i] = blockedOf(sn.Series[Serve][i], sn.Series[Deny][i], sn.Series[Solve][i], sn.Series[Abandon][i])
	}
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
