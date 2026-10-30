package handlers

import (
	"net/netip"
	"strings"

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

// PassIdentity names the pass a logged request rode on the way the plugin's
// $unmask_bv_id does (cookies.PassID): the signature of a CAPTCHA-form entry,
// the seed a proof-of-work answers -- so every nonce that answers one seed is
// one pass, as it is one budget for the per-pass reuse cap.  "" when no
// entry verifies.  The access-log reader keys its per-address count of
// distinct passes by it, so the count says how many budgets an address holds.
func (h *Handler) PassIdentity(value, ip, host string) string {
	cfg := h.cfg()
	if cfg.Secret.BVSecret == "" || value == "" || len(value) > 1024 {
		return ""
	}
	ch := cfg.Challenge.Resolve(host)
	pow, captcha, diff := ch.PowCookieValidSecondsResolved(), ch.CaptchaCookieValidSecondsResolved(), ch.ResolvedPowDifficulty()
	if _, _, id, _, ok := cookies.MatchingEntryID(value, cfg.Secret.BVSecret, ip, host, pow, captcha, diff); ok {
		return id
	}
	if k := relayBindKey(ip); k != "" {
		if _, _, id, _, ok := cookies.MatchingEntryID(value, cfg.Secret.BVSecret, k, host, pow, captcha, diff); ok {
			return id
		}
	}
	return ""
}

// sigHash: the MAC this install signs its cookies and seeds with
// (settings.secret.sig_hash; cookies.DefaultSigHash when it names none or
// names nothing the daemon knows -- Load warned about that).
func (h *Handler) sigHash() cookies.SigHash {
	v, ok := cookies.ParseSigHash(strings.TrimSpace(h.cfg().Secret.SigHash))
	if !ok {
		return cookies.DefaultSigHash
	}
	return v
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
