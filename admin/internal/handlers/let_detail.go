package handlers

import (
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// What a bypass matched, for the access log's reader (nginxlog's
// SetLetThroughDetail): the range an address is in, the bypass path row a
// path matches.  The matcher is kept the way the ban guard's is
// (ban_bypass.go) -- for one published settings snapshot, one load of the
// crawler ranges, and letDetailMaxAge at most -- since it is asked for every
// line nginx let through on a bypass.
var (
	letDetailMu    sync.Mutex
	letDetailSnap  *settings.Settings
	letDetailGen   uint64
	letDetailBuilt time.Time
	letDetailM     *nginxconf.LetDetail
)

const letDetailMaxAge = 10 * time.Minute

func (h *Handler) letDetail() *nginxconf.LetDetail {
	snap := h.cfg()
	gen := nginxconf.IPRangeGeneration()
	letDetailMu.Lock()
	defer letDetailMu.Unlock()
	if letDetailM == nil || letDetailSnap != snap || letDetailGen != gen || time.Since(letDetailBuilt) > letDetailMaxAge {
		letDetailM = nginxconf.NewLetDetail(snap.Nginx)
		letDetailSnap, letDetailGen, letDetailBuilt = snap, gen, time.Now()
	}
	return letDetailM
}

// LetDetailIP names the bypass range ip is in: a preset's id, or
// nginxconf.LetDetailOwn and the operator's row.  "" when it is in none.
func (h *Handler) LetDetailIP(ip string) string { return h.letDetail().IP(ip) }

// LetDetailPath names the bypass path row that matches path on host.
func (h *Handler) LetDetailPath(host, path string) string { return h.letDetail().Path(host, path) }
