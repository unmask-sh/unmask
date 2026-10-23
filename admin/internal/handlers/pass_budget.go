package handlers

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// solveBudget counts, per client -- an address and a TLS fingerprint -- the
// proof-of-work passes of the last day, for the pass budget
// (settings.RateLimit.PassBudget).  In memory: the count is a day's, and a
// restart forgets it, which errs towards the client.
type solveBudget struct {
	mu      sync.Mutex
	counts  map[string]*solveCount
	sweptAt time.Time
	// sig is the part of the settings whose change makes every client solve
	// again -- the cookie secret, the difficulty, the cookie's lifetime --
	// and changedAt when it last did.  For a day after, nothing is banned: a
	// shared address re-solving for everyone behind it looks exactly like a
	// page-by-page solver.
	sig       string
	changedAt time.Time
}

// solveCount is one client's day.
type solveCount struct {
	n      int
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

// add counts one pass for key under the settings signature sig and returns
// the day's count and whether the budget is settling after a settings change
// (when nothing is banned).
func (b *solveBudget) add(key, sig string, now time.Time) (n int, settling bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
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
		c = &solveCount{since: now}
		b.counts[key] = c
	}
	c.n++
	return c.n, !b.changedAt.IsZero() && now.Sub(b.changedAt) < solveBudgetWindow
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

// countPass counts one recorded challenge pass for the client and bans it
// when it is over the pass budget.  Called once per pass: for the beacon
// kept, or for the /bvj issue's record when the beacon never came
// (pass_trace.go).  An address on the bypass list, with the crawler ranges
// it carries, is not counted.  A CAPTCHA pass counts like a proof-of-work
// pass: the built-in CAPTCHA is answered by a script in two requests, and
// a client that answers it on every page is the client this budget is for.
// Five hundred solves of either kind in a day is not a person.
func (h *Handler) countPass(ip, ja4, site, kind string) {
	if (kind != "pow2" && kind != "captcha") || ip == "" || h.BanMgr == nil {
		return
	}
	cfg := h.cfg()
	if !nginxconf.PassBudgetActive(*cfg) {
		return
	}
	if h.bypassMatchers(cfg, "").ipBypass.Match(ip) {
		return
	}
	// The settings every client re-solves after: the default challenge's,
	// since one signature serves every site.
	def := cfg.Challenge.Default
	sig := cfg.Secret.BVSecret + "|" + strconv.Itoa(def.ResolvedPowDifficulty()) + "|" + strconv.Itoa(def.PowCookieValidSecondsResolved())
	pb := cfg.RateLimit.PassBudget
	key := budgetAddr(ip) + "|" + ja4
	n, settling := h.solveBudget.add(key, sig, time.Now())
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
