package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The pass-cookie reuse cap (settings.rate_limit.reuse).
//
// Every rate limit counts only requests without a valid _bv (a deny zone
// aside), so a client that solved the challenge once -- a PoW takes a real
// browser a fraction of a second -- is not counted again while its cookie
// lives, on every node that shares the secret.  The cap is a set of nginx
// zones that count only the requests WITH a valid _bv
// (nginxconf.ReuseZoneRender): one pass at a time (keyed on the plugin's
// $unmask_bv_id), and per client address.  Over any of them, nginx sends the
// request down the rate route like any zone; this file tells the cap's hits
// from the others.
//
// A solved CAPTCHA is not counted by the address zone, and while the
// per-pass tier is held by the upgrade review (nginxconf.ReusePassActive) not
// here either.  That CAPTCHA is how a person behind a busy address (an office
// proxy, a carrier NAT) gets past the address's budget; counted there, the
// next request from the same address would be over it again and they could
// never get through (2026-10-06: an office behind one address went past the
// default budget every weekday).  The per-pass tier counts it like any pass:
// its holder over that budget is served a CAPTCHA again, and the solve is a
// new pass with a budget of its own, so nobody is held.

// reuseCapKey marks a rate-route request as the reuse cap's, for the
// challenge renderers downstream of ServeChallengeOrJSON, with the seconds
// its answer gives in Retry-After (nginxconf.ReuseRetryAfter).
type reuseCapKey struct{}

func withReuseCap(r *http.Request, retryAfter int) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), reuseCapKey{}, retryAfter))
}

func reuseCapped(r *http.Request) bool {
	_, ok := reuseCapRetryAfter(r)
	return ok
}

// reuseCapRetryAfter: the Retry-After of the reuse cap's answer, false for a
// request that is not the cap's.
func reuseCapRetryAfter(r *http.Request) (int, bool) {
	secs, ok := r.Context().Value(reuseCapKey{}).(int)
	return secs, ok && secs > 0
}

// reuseCapHit reports whether a rate-route request (/_rl/...) is over the
// reuse cap, the cap's action, and the Retry-After its answer gives: when
// the zones that count this pass let the next request in.  nginx says only
// that some zone is over.
// The cap's zones are the ones that count a request carrying a valid _bv,
// apart from a deny zone (the caller has already served those) and the ASN /
// country rate rules, which count everyone in their network.  So the answer is
// yes when the cap is in force, the request carries a valid _bv a zone of
// the cap counts -- any pass with the per-pass tier in force, anything but a
// solved CAPTCHA without it -- and the client falls under no ASN / country
// rate rule and matched no custom rule with a rate limit of its own: under
// one of those, the two cannot be told apart, and that rule's own action is
// served as before.
func (h *Handler) reuseCapHit(r *http.Request, site string) (action string, retryAfter int, ok bool) {
	cfg := *h.cfg()
	if !nginxconf.ReuseCapActive(cfg) {
		return "", 0, false
	}
	bv, kind := pickValidBV(r, cfg, bindKeyFor(r), site)
	if bv == "" || (kind == "captcha" && !nginxconf.ReusePassActive(cfg)) {
		return "", 0, false
	}
	// The visitor's network (clientIP), the one nginx counted the request
	// under -- not the connection's peer's, which behind a remote nginx is
	// that nginx.
	if _, matched := h.netRateRule(clientIP(r), cfg); matched {
		return "", 0, false
	}
	if throttledRuleMatched(r, cfg) {
		return "", 0, false
	}
	return cfg.RateLimit.Reuse.ResolvedAction(), nginxconf.ReuseRetryAfter(cfg, kind == "captcha"), true
}

// throttledRuleMatched: whether the request matched a custom rule that
// carries a rate limit of its own.  Such a rule's zone counts everyone the
// rule matches, pass holders included, and the conf names the rule on the
// rate route (X-Unmask-Rule, set by the proxy, never by the client); under
// one, a pass holder over "some zone" cannot be told from a pass holder over
// the rule's, and the rule's own answer is served as before -- the policy the
// ASN / country rate rules already get.  A rule without a rate limit has no
// zone, so a pass holder on the rate route under it is the cap's.
func throttledRuleMatched(r *http.Request, cfg settings.Settings) bool {
	id := strings.TrimSpace(r.Header.Get("X-Unmask-Rule"))
	if id == "" {
		return false
	}
	for _, cr := range cfg.Nginx.CustomRules {
		if cr.ID == id {
			return cr.RatePerMin > 0
		}
	}
	return false
}

// netRateRule: the ASN / country rate rule the client falls under, if any,
// with its action ("" when the rule leaves it to the default).  ASN first,
// as the more specific.
func (h *Handler) netRateRule(ip string, cfg settings.Settings) (string, bool) {
	if h.IPGeo == nil || ip == "" {
		return "", false
	}
	info := h.IPGeo.LookupInfo(ip)
	if h.IPGeo.ASNLoaded() {
		for _, rr := range cfg.Nginx.Asn.RateRules() {
			if (rr.ASN != 0 && info.ASN == rr.ASN) ||
				(rr.ASN == 0 && rr.Org != "" && settings.OrgMatchesAny(info.ASNOrg, []string{rr.Org})) {
				return rr.Action, true
			}
		}
	}
	if h.IPGeo.Loaded() {
		cc := strings.ToUpper(strings.TrimSpace(info.Country))
		for _, rr := range cfg.Nginx.Geo.RateRules() {
			if rr.Country == cc {
				return rr.Action, true
			}
		}
	}
	return "", false
}
