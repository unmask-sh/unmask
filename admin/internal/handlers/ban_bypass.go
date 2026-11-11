package handlers

import (
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
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
