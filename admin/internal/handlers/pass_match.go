package handlers

import (
	"net/netip"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/relay"
)

// MatchPassEntry names the pass a logged request rode on: the entry of the
// _bv value that verifies for the client the way the plugin verified it --
// bound to the address (a relay's range or id for a client inside one) and
// the host, within the kind's window, at the site's difficulty.  "" when none
// does.  The access-log reader keys its per-address count of distinct passes
// by it (nginxlog.Reader.SetPassMatcher): a browser carrying a pass per
// network it solved on counts once per network, and a client padding its
// cookie with junk entries counts for the one that verified, not for the
// padding.  Runs on the log reader's goroutine, never on a request path.
func (h *Handler) MatchPassEntry(value, ip, host string) string {
	cfg := h.cfg()
	if cfg.Secret.BVSecret == "" || value == "" || len(value) > 1024 {
		return ""
	}
	ch := cfg.Challenge.Resolve(host)
	pow, captcha, diff := ch.PowCookieValidSecondsResolved(), ch.CaptchaCookieValidSecondsResolved(), ch.ResolvedPowDifficulty()
	if e, _, _, ok := cookies.MatchingEntry(value, cfg.Secret.BVSecret, ip, host, pow, captcha, diff); ok {
		return e
	}
	// Inside a relay's published range the pass is bound to the range, or
	// to the relay's id -- the key http.inc hands the daemon as
	// X-Unmask-Bind-Key on a request; the log carries the address alone.
	if k := relayBindKey(ip); k != "" {
		if e, _, _, ok := cookies.MatchingEntry(value, cfg.Secret.BVSecret, k, host, pow, captcha, diff); ok {
			return e
		}
	}
	return ""
}

// relayBindKey is the key a pass from a relay's range is bound to -- the
// listed prefix, or the relay's id when it is bound as a whole -- and "" for
// an address outside every range.  The same table nginxconf renders into
// http.inc's $unmask_bind_key, so both sides name the key alike.
func relayBindKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	p, hit, ok := relay.Active().LookupPrefix(a)
	if !ok {
		return ""
	}
	if hit.Key != "" {
		return hit.Key
	}
	return p.Masked().String()
}
