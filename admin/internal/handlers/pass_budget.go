package handlers

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// solveBudget counts, per client -- an address and a TLS fingerprint -- the
// distinct passes of the last day, for the pass budget
// (settings.RateLimit.PassBudget).  A pass is counted once whichever trace
// brings it: the page's own report, the /bvj issue, or the access log, where
// every request names the pass it rode on.  The log is what makes the count
// the daemon's rather than the client's: a client that mints its cookies
// itself sends no report, but it cannot use a pass without presenting it.
// In memory: the count is a day's, and a restart forgets it, which errs
// towards the client.
type solveBudget struct {
	mu      sync.Mutex
	counts  map[string]*solveCount
	sweptAt time.Time
	// seq numbers a pass reported without an identity, so each is its own.
	seq uint64
	// sig is the part of the settings whose change makes every client solve
	// again -- the cookie secret, the difficulty, the cookie's lifetime --
	// and changedAt when it last did.  For a day after, nothing is banned: a
	// shared address re-solving for everyone behind it looks exactly like a
	// page-by-page solver.
	sig       string
	changedAt time.Time
}

// solveCount is one client's day: the passes seen, by identity, up to one
// past the budget (past it the client is banned and the set has said what
// it has to say), and how many that is.
type solveCount struct {
	ids    map[uint64]struct{}
	since  time.Time
	banned bool
}

const (
	// solveBudgetWindow is the budget's day.
	solveBudgetWindow = 24 * time.Hour
	// solveBudgetKeysMax bounds the clients counted; past it the counts
	// start over, erring towards the client.
	solveBudgetKeysMax = 200000
)

// add counts the pass id for key under the settings signature sig -- once,
// however many times it is reported -- and returns the day's count of
// distinct passes and whether the budget is settling after a settings change
// (when nothing is banned).  limit bounds the identities kept per client.
// An id of zero is a pass with no identity, counted as one of its own.
func (b *solveBudget) add(key, sig string, id uint64, limit int, now time.Time) (n int, settling bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if id == 0 {
		b.seq++
		id = b.seq
	}
	if b.sig != sig {
		if b.sig != "" { // the first sight is not a change
			b.changedAt = now
		}
		b.sig = sig
		b.counts = nil
	}
	if b.counts == nil || len(b.counts) >= solveBudgetKeysMax {
		b.counts, b.sweptAt = map[string]*solveCount{}, now
	} else if now.Sub(b.sweptAt) > time.Hour {
		for k, c := range b.counts {
			if now.Sub(c.since) > solveBudgetWindow {
				delete(b.counts, k)
			}
		}
		b.sweptAt = now
	}
	c := b.counts[key]
	if c == nil || now.Sub(c.since) > solveBudgetWindow {
		c = &solveCount{since: now, ids: map[uint64]struct{}{}}
		b.counts[key] = c
	}
	if _, seen := c.ids[id]; !seen && len(c.ids) <= limit {
		c.ids[id] = struct{}{}
	}
	return len(c.ids), !b.changedAt.IsZero() && now.Sub(b.changedAt) < solveBudgetWindow
}

// markBanned remembers that key's ban is placed and says whether this is the
// first time: the passes that still arrive before the ban bites are not each
// a ban.
func (b *solveBudget) markBanned(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.counts[key]
	if c == nil || c.banned {
		return false
	}
	c.banned = true
	return true
}

// countPass counts one challenge pass for the client and bans it when its
// day's distinct passes are over the pass budget.  id is the pass's
// identity (cookies.MatchingEntryID: what the plugin's $unmask_bv_id names,
// so a pass is one whichever trace reports it -- the page's beacon, the
// /bvj issue, or the access log through ObservePass); "" is a pass of its
// own.  An address on the bypass list, with the crawler ranges it carries,
// is not counted, nor is an address inside a relay's published range: its
// passes are bound to the range and used from every exit of it, so the
// exits would each see the passes of everyone behind the relay.  A CAPTCHA
// pass counts like a proof-of-work pass: a client that clears the
// challenge on every page is the client this budget is for, whichever leg
// it cleared.  Five hundred passes of either kind in a day is not a person.
func (h *Handler) countPass(ip, ja4, site, kind, id string) {
	if kind == "pow" {
		kind = "pow2" // the log names the proof-of-work kind the way the plugin does
	}
	if (kind != "pow2" && kind != "captcha") || ip == "" || h.BanMgr == nil {
		return
	}
	cfg := h.cfg()
	if !nginxconf.PassBudgetActive(*cfg) {
		return
	}
	if h.bypassMatchers(cfg, "").ipBypass.Match(ip) || relayBindKey(ip) != "" {
		return
	}
	// The settings every client re-solves after: the default challenge's,
	// since one signature serves every site.
	def := cfg.Challenge.Default
	sig := cfg.Secret.BVSecret + "|" + strconv.Itoa(def.ResolvedPowDifficulty()) + "|" + strconv.Itoa(def.PowCookieValidSecondsResolved())
	pb := cfg.RateLimit.PassBudget
	key := budgetAddr(ip) + "|" + ja4
	n, settling := h.solveBudget.add(key, sig, passIDHash(id), pb.ResolvedPerDay(), time.Now())
	if settling || n <= pb.ResolvedPerDay() || !h.solveBudget.markBanned(key) {
		return
	}
	scope := ban.ScopeIPJA4
	if ja4 == "" {
		scope = ban.ScopeIPOnly
	}
	reason := fmt.Sprintf("pass budget: %d challenge passes in a day (budget %d)", n, pb.ResolvedPerDay())
	if site != "" {
		reason += " on " + site
	}
	h.BanMgr.AddAuto(context.Background(), ip, ja4, scope, ban.SourceRateLimitAbuse, reason,
		pb.ResolvedAction(), int64(pb.ResolvedBanHours())*3600)
}

// ObservePass is the access-log reader's report of a pass an address
// presented for the first time in a day (nginxlog.Reader.SetPassObserver):
// the budget's count from what the daemon saw rather than what the client
// reported.  Runs on the reader's goroutine.
func (h *Handler) ObservePass(ip, ja4, site, kind, id string) {
	h.countPass(ip, safeJA4(ja4), site, kind, id)
}

// passIDHash folds a pass's identity to the key the budget's set holds; 0
// for none.
func passIDHash(id string) uint64 {
	if id == "" {
		return 0
	}
	f := fnv.New64a()
	f.Write([]byte(id))
	return f.Sum64()
}

// budgetAddr is the address the pass budget counts under.  An IPv6 client
// holds a /64 at the least and a VPS a /48, so counting per address let one
// machine draw on sixty-five thousand budgets; the pass cookie is bound to
// the /64, and the budget folds further to the /48.  IPv4 is itself.
func budgetAddr(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() || a.Is4In6() {
		return ip
	}
	return netip.PrefixFrom(a, 48).Masked().Addr().String()
}
