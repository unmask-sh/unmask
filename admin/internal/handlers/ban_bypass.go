package handlers

import (
	"net/netip"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/relay"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The ban guard's allowlist (nginxconf.NewIPBypassMatcher: the crawler
// ranges and the operator's bypass addresses) was built anew for every ban
// it vetted -- some 4,700 ranges parsed, about 6 ms, on the access log's
// worker for every honeypot hit, so a client hammering a trap kept the
// worker busy until the socket dropped lines.  It is kept now for one
// published settings snapshot (a save swaps the pointer), one load of the
// crawler ranges (nginxconf.IPRangeGeneration) and banBypassMaxAge at most,
// as the automatic presets also depend on how old the ranges are.
var (
	banBypassMu    sync.Mutex
	banBypassSnap  *settings.Settings
	banBypassGen   uint64
	banBypassBuilt time.Time
	banBypassM     *nginxconf.IPBypassMatcher
)

const banBypassMaxAge = 10 * time.Minute

// BanBypassMatch: whether ip is on the ban guard's allowlist (the ban
// manager's whitelist).
func (h *Handler) BanBypassMatch(ip string) bool {
	snap := h.cfg()
	gen := nginxconf.IPRangeGeneration()
	banBypassMu.Lock()
	if banBypassM == nil || banBypassSnap != snap || banBypassGen != gen || time.Since(banBypassBuilt) > banBypassMaxAge {
		banBypassM = nginxconf.NewIPBypassMatcher(snap.Nginx)
		banBypassSnap, banBypassGen, banBypassBuilt = snap, gen, time.Now()
	}
	m := banBypassM
	banBypassMu.Unlock()
	return m.Match(ip)
}

// BanSharedExit: the relay ip is a shared exit of -- iCloud Private Relay, a
// secure web gateway: the relay list, while it is in use (relay.Active) --
// for the ban manager, which places no automatic ban on such an address
// (ban.Manager.SetSharedExit).  Everyone the relay sends out through the
// address shares it: one visitor's request to a trap banned them all.
func (h *Handler) BanSharedExit(ip string) (string, bool) {
	t := relay.Active()
	if t == nil {
		return "", false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	hit, ok := t.Lookup(a)
	if !ok {
		return "", false
	}
	return relay.Name(hit.Relay), true
}
