package handlers

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// passTrace is what the daemon keeps in memory about the challenge page's
// beacons and the passes they report.
//
// The beacon's per-address limit used to be read off the event table: the
// rows of the last five minutes, the serve rows the daemon writes itself
// among them.  An address challenged twenty times in five minutes could then
// send no beacon at all, and a client that solves the proof-of-work on every
// page -- the one an operator most wants to see -- lost nearly all of its
// pass beacons (one in seventy kept, in the reported case).  The limit counts
// beacons now, here, without a query per beacon.  A pass beacon the request's
// own cookie vouches for is outside the limit, since nobody sends one without
// a solve behind it; a pass is one record whichever of its two traces arrives
// first, the page's beacon or the /bvj issue; and the beacons the limit drops
// are counted per address, so the hunt can say what the log does not hold.
type passTrace struct {
	mu sync.Mutex

	// budget is the beacons each address sent in the current window.  The
	// window is one for every address, as the held-beacon count's was: a
	// coarse clock, and a cheap one.
	budget      map[string]int
	budgetSince time.Time

	// dropped is the beacons the budget refused, per address, kept for a day
	// past the last one.
	dropped map[string]*droppedBeacons

	// seen is the passes recorded, by bind key and entry, for as long as a
	// pass can still be reported.
	seen    map[string]*passSeen
	sweptAt time.Time
}

// droppedBeacons is one address's count of refused beacons.
type droppedBeacons struct {
	Total int
	Last  time.Time
}

// passSeen is one pass's record state: which trace kept it.
type passSeen struct {
	at         time.Time
	beacon     bool // the page's beacon was kept
	bvj        bool // the /bvj issue's record was written
	bvjPending bool // the /bvj issue is waiting for the page's beacon
}

const (
	// passTraceWindow is the beacon budget's window.
	passTraceWindow = 5 * time.Minute
	// passTraceFresh is how old a pass may be and still be this page's: the
	// beacon token's own lifetime.
	passTraceFresh = beaconTokenTTL
	// passTraceDroppedKeep is how long an address's dropped count outlives
	// its last drop.
	passTraceDroppedKeep = 24 * time.Hour
	// passTraceAddrsMax bounds the addresses counted; past it the counts
	// start over, erring towards keeping a beacon.
	passTraceAddrsMax = 100000
	// passTraceSeenMax bounds the passes remembered the same way.
	passTraceSeenMax = 200000
	// passTraceDefaultLimit stands in for a limit the settings left at zero.
	passTraceDefaultLimit = 20
)

// passTraceGrace is how long the /bvj issue waits for the page's own beacon
// before it writes the pass itself.  The two leave the page in the same tick
// and arrive in either order; a variable so a test need not wait.
var passTraceGrace = 3 * time.Second

// take counts one beacon from addr against limit and says whether it is
// within it.  A refused beacon is counted as dropped.
func (p *passTrace) take(addr string, limit int, now time.Time) bool {
	if limit <= 0 {
		limit = passTraceDefaultLimit
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.budget == nil || now.Sub(p.budgetSince) > passTraceWindow || len(p.budget) >= passTraceAddrsMax {
		p.budget, p.budgetSince = map[string]int{}, now
	}
	if p.budget[addr] >= limit {
		p.drop(addr, now)
		return false
	}
	p.budget[addr]++
	return true
}

// takeQuiet is take for a budget that is not a beacon's: the refusal is
// counted against the key like any other, but not recorded as a dropped
// beacon of the address (the hunt would otherwise report questions a
// script drew as beacons it lost).
func (p *passTrace) takeQuiet(key string, limit int, now time.Time) bool {
	if limit <= 0 {
		limit = passTraceDefaultLimit
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.budget == nil || now.Sub(p.budgetSince) > passTraceWindow || len(p.budget) >= passTraceAddrsMax {
		p.budget, p.budgetSince = map[string]int{}, now
	}
	if p.budget[key] >= limit {
		return false
	}
	p.budget[key]++
	return true
}

// drop counts a refused beacon from addr.  The caller holds the lock.
func (p *passTrace) drop(addr string, now time.Time) {
	if p.dropped == nil || len(p.dropped) >= passTraceAddrsMax {
		p.dropped = map[string]*droppedBeacons{}
	}
	d := p.dropped[addr]
	if d == nil {
		d = &droppedBeacons{}
		p.dropped[addr] = d
	}
	d.Total++
	d.Last = now
}

// droppedFor is how many beacons from addr the budget refused, and when the
// last was; zero once a day has passed since the last.
func (p *passTrace) droppedFor(addr string, now time.Time) (int, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := p.dropped[addr]
	if d == nil || now.Sub(d.Last) > passTraceDroppedKeep {
		return 0, time.Time{}
	}
	return d.Total, d.Last
}

// beaconPass records that the page's beacon reports the pass key and says
// whether it is the first trace of it: true keeps the beacon, false means the
// pass is recorded already (the same beacon again, or the /bvj issue's record
// written after its grace).  A /bvj issue still waiting is overtaken: its
// timer finds the beacon kept and writes nothing.
func (p *passTrace) beaconPass(key string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.seenEntry(key, now)
	if s.beacon || s.bvj {
		return false
	}
	s.beacon = true
	return true
}

// bvjPass records that the /bvj issue saw the pass key and says whether its
// record is to be scheduled: false when the page's beacon was kept already,
// or an issue's record is pending or written.
func (p *passTrace) bvjPass(key string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.seenEntry(key, now)
	if s.beacon || s.bvj || s.bvjPending {
		return false
	}
	s.bvjPending = true
	return true
}

// bvjFire runs when the /bvj issue's grace is over: true when the page's
// beacon never came and the issue's record is to be written now.
func (p *passTrace) bvjFire(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.seen[key]
	if s == nil {
		return true // forgotten meanwhile (the table was full); written rather than lost
	}
	s.bvjPending = false
	if s.beacon {
		return false
	}
	s.bvj = true
	return true
}

// seenEntry returns the record for key, made if new, sweeping the passes
// that can no longer be reported.  The caller holds the lock.
func (p *passTrace) seenEntry(key string, now time.Time) *passSeen {
	if p.seen == nil || len(p.seen) >= passTraceSeenMax {
		p.seen, p.sweptAt = map[string]*passSeen{}, now
	} else if now.Sub(p.sweptAt) > time.Minute {
		for k, s := range p.seen {
			if !s.bvjPending && now.Sub(s.at) > passTraceFresh+passTraceGrace {
				delete(p.seen, k)
			}
		}
		p.sweptAt = now
	}
	s := p.seen[key]
	if s == nil {
		s = &passSeen{at: now}
		p.seen[key] = s
	}
	return s
}

// isPassPhase: the beacon phases that report a pass, the "bv_" + mode family.
// The rebind phases are the daemon's own rows.
func isPassPhase(phase string) bool {
	switch phase {
	case string(events.PhaseBVPowOnly), string(events.PhaseBVCaptchaOnly), string(events.PhaseBVPowThenCaptcha):
		return true
	}
	return false
}

// vouchedPass finds, among the request's _bv cookies, a fresh entry that
// verifies for the request's bind key and host: the pass the request itself
// proves it holds.  It returns the pass key (bind key and entry) and the
// entry's kind, or "" when the request holds none.  A rebound entry does not
// count: it records a roam, not a solve, and the rebind path writes its own
// row.  Freshness is the beacon token's lifetime, measured from the issue
// time the entry carries, which the server supplied.
func (h *Handler) vouchedPass(r *http.Request, site string, now time.Time) (key, kind string) {
	cfg := h.cfg()
	ch := cfg.Challenge.Resolve(site)
	bind := bindKeyFor(r)
	host := requestHost(r)
	for _, c := range r.Cookies() {
		if c.Name != "_bv" || c.Value == "" || len(c.Value) > 1024 {
			continue
		}
		entry, k, issued, ok := cookies.MatchingEntry(c.Value, cfg.Secret.BVSecret, bind, host,
			ch.PowCookieValidSecondsResolved(), ch.CaptchaCookieValidSecondsResolved(), ch.ResolvedPowDifficulty())
		if !ok || k == "rebind" {
			continue
		}
		if age := now.Unix() - issued; age > int64(passTraceFresh/time.Second) || age < -60 {
			continue
		}
		return bind + "|" + entry, k
	}
	return "", ""
}

// recordBVJPass keeps the pass the /bvj issue proves, should the page's own
// beacon not arrive within the grace.  The proof-of-work path mints its
// cookie on the client, so that beacon and this issue are the daemon's only
// traces of the solve, and the beacon's budget used to drop nearly all of
// them.  The CAPTCHA path's passes are issued by the daemon, in the verify
// response, and their beacons are vouched for the same way.
func (h *Handler) recordBVJPass(r *http.Request, site, key, kind string) {
	if kind != "pow2" {
		return
	}
	ev := h.passEvent(r, site, events.PhaseBVPowOnly, "bvj")
	if ev == nil || !h.passTrace.bvjPass(key, time.Now()) {
		return
	}
	ip := clientIP(r)
	time.AfterFunc(passTraceGrace, func() {
		if h.passTrace.bvjFire(key) {
			events.InsertAsync(h.DB, ev)
			h.countPass(ip, ev.JA4, site, kind) // the beacon never came: this is the pass's one count
		}
	})
}

// passEvent is the pass row the daemon writes itself, in the beacon's shape
// so the hunt, the funnels and the advisor read it as one.  The payload's
// "trace" names the path that wrote it; the page's beacons carry none.  nil
// when the request names no address.
func (h *Handler) passEvent(r *http.Request, site string, phase events.Phase, trace string) *events.Event {
	pkt := events.PackIP(clientIP(r))
	if pkt == nil {
		return nil
	}
	ja4 := safeJA4(strings.TrimSpace(r.Header.Get("X-Client-JA4")))
	verdict := h.resolvedVerdictName(ja4) // unmask-derived (not the X-JA4-Verdict header)
	return &events.Event{
		Site:         site,
		Host:         h.HostID,
		Scheme:       schemeFromRequest(r),
		Port:         portFromRequest(r),
		IPPacked:     pkt,
		UserAgent:    r.Header.Get("User-Agent"),
		JA4:          ja4,
		JA4Verdict:   verdict,
		JA4VerdictID: h.VerdictNameToID(verdict),
		Phase:        string(phase),
		CookieBV:     readCookieMax(r, "_bv", 1024),
		CookieBR:     readCookieMax(r, "_br", 8),
		Payload: map[string]any{
			"trace":         trace,
			"pass_verified": 1,
		},
	}
}
