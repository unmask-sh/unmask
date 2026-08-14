// Core of forward-auth mode.
//
// Flow:
//
//	client -> HTTP server (= nginx / Apache / etc.)
//	                    | subrequest (= auth_request / forward_auth / ext_authz)
//	                    v
//	       /unmask/api/check  <- this endpoint
//	                    |
//	                    +-> 200 OK         : let through (= forward normally)
//	                        401 Unauthorized: challenge needed (= server redirects to /unmask/challenge/)
//	                        403 Forbidden   : block (= persistent BAN / honeypot trip)
//
// Inputs from the HTTP server come as headers:
//
//	X-Original-URI    original request path + query
//	X-Original-IP     client IP (= equivalent to nginx/Apache's $remote_addr)
//	X-Original-UA     User-Agent
//	X-Original-Host   Host header
//	X-Unmask-Site     (= optional) multi-site identifier
//	Cookie            client cookies including _bv / _br (= passed by the server)
//
// Response headers:
//
//	X-Unmask-Action   pass | challenge | block
//	X-Unmask-Reason   human-readable reason (e.g. "ban:honeypot", "ua:user_dev")
package handlers

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/crawlerverify"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/privacypass"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/webbotauth"
)

// wbaVerifyRequest reconstructs the CLIENT's request for signature
// verification.  /_unmask/check is reached via a subrequest / forward-auth
// hop, so the inbound r describes the hop, not what the bot signed: r.Host is
// the admin upstream ("unmask" / "admin:9477") and r.URL is /_unmask/check.
// A bot signs derived components of ITS request — "@authority" = the target
// site's host, "@path" = the fetched path — so verifying against the raw r
// can never match (= every signature would fail with "signature mismatch").
// Rebuild those components from the X-Original-* headers the proxy snippet
// forwards (same trust level as the rest of this handler, which already
// drives its decisions off X-Original-URI / -Host / -IP).  The signature
// headers themselves travel in r.Header and are used as-is.
func wbaVerifyRequest(r *http.Request) *http.Request {
	vr := r.Clone(r.Context())
	if h := r.Header.Get("X-Original-Host"); h != "" {
		vr.Host = h
	}
	if u := r.Header.Get("X-Original-URI"); u != "" {
		if parsed, err := url.ParseRequestURI(u); err == nil {
			vr.URL = parsed
		}
	}
	if m := r.Header.Get("X-Original-Method"); m != "" {
		vr.Method = m
	}
	// Absolute-URL pieces for "@target-uri" / "@scheme".  The public side of
	// every supported deployment terminates TLS (the challenge flow assumes
	// it), so https is the right default when the proxy didn't say.
	vr.URL.Host = vr.Host
	if proto := r.Header.Get("X-Original-Proto"); proto != "" {
		vr.URL.Scheme = proto
	} else {
		vr.URL.Scheme = "https"
	}
	return vr
}

// axisSeverity: how restrictive an axis vote is.  Higher = stronger.
// Used by the max-severity decision pipeline so multiple axes (geo /
// honeypot / ban / protected / ja4 / UA) can each contribute a vote and
// the harshest one wins.  The values map directly to the rate-challenge
// modes plus an explicit "pass" floor.
type axisSeverity int

const (
	sevPass           axisSeverity = 0
	sevPoWOnly        axisSeverity = 1
	sevCaptchaOnly    axisSeverity = 2
	sevPoWThenCaptcha axisSeverity = 3
	sevDeny           axisSeverity = 4
)

// axisDecision: one axis' vote.  Empty (= sevPass with no reason) means the
// axis chose not to contribute.  reason is a short label for analytics /
// audit; chMode is the chain-mode string for challenge votes (= empty for
// pass / deny).
type axisDecision struct {
	sev    axisSeverity
	reason string
	chMode string
}

// severityFromAction maps an action / chMode string into the severity scale.
// Empty / "pass" / "skip" all map to sevPass (= floor).
func severityFromAction(s string) axisSeverity {
	switch s {
	case "", "pass", settings.GeoActionSkip:
		return sevPass
	case settings.RateChallengePoWOnly:
		return sevPoWOnly
	case settings.RateChallengeCaptchaOnly:
		return sevCaptchaOnly
	case settings.RateChallengePoWThenCaptcha:
		return sevPoWThenCaptcha
	case settings.RateChallengeDeny:
		return sevDeny
	}
	return sevPass
}

// chModeFromSeverity returns the canonical chMode string for a severity
// (= used to surface chMode to the challenge HTML when an axis wins).
// sevPass and sevDeny intentionally return "" (= no chain needed).
func chModeFromSeverity(s axisSeverity) string {
	switch s {
	case sevPoWOnly:
		return settings.RateChallengePoWOnly
	case sevCaptchaOnly:
		return settings.RateChallengeCaptchaOnly
	case sevPoWThenCaptcha:
		return settings.RateChallengePoWThenCaptcha
	}
	return ""
}

// pickStrongest returns the highest-severity decision and a list of
// suppressed reasons from the runners-up (= for "geo:JP:pow_only suppressed
// by ja4:captcha_only" transparency).  Empty input -> implicit pass.
func pickStrongest(decisions []axisDecision) (axisDecision, []string) {
	winner := axisDecision{sev: sevPass}
	for _, d := range decisions {
		if d.sev > winner.sev {
			winner = d
		}
	}
	if winner.sev == sevPass {
		return winner, nil
	}
	suppressed := make([]string, 0, len(decisions))
	for _, d := range decisions {
		if d.sev == sevPass || d.reason == winner.reason {
			continue
		}
		suppressed = append(suppressed, d.reason)
	}
	return winner, suppressed
}

// AuthCheck: GET / POST /unmask/api/check (= auth_request endpoint).
//
// nginx's auth_request is GET and Apache's ProxyPass + auth is GET; other
// forward-auth proxies may use POST.  Accept all.
func (h *Handler) AuthCheck(w http.ResponseWriter, r *http.Request) {
	// Fail CLOSED on a panic.  net/http recovers a handler panic but drops the
	// connection with no response, and the shipped forward-auth snippets map a
	// 5xx subrequest to @unmask_fail_open (return 200) -- so an unrecovered
	// panic here is a CHALLENGE BYPASS, not just an error.  Recover and answer
	// 401 (challenge) so a bug/hostile-input panic cannot pass a request.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("PANIC recovered in AuthCheck (failing closed to challenge): %v\n%s", rec, debug.Stack())
			w.Header().Set("X-Unmask-Action", "challenge")
			w.Header().Set("X-Unmask-Reason", "internal_error")
			w.WriteHeader(http.StatusUnauthorized)
		}
	}()
	// 1. extract inputs.  Prefer X-Original-* headers (= when via subrequest).
	ip := firstNonEmpty(
		r.Header.Get("X-Original-IP"),
		r.Header.Get("X-Real-IP"),
		clientIP(r),
	)
	// The proxy's X-Original-UA is authoritative even when it is EMPTY: an
	// empty value means the visitor sent no User-Agent, which is a signal in
	// its own right and one of the strongest bot tells there is.  Falling
	// through to this request's own User-Agent would replace that fact with
	// the fetcher's identity -- under Apache/mod_lua the subrequest is made by
	// luasocket, so every UA-less visitor was recorded as "LuaSocket 3.0.0"
	// and classified as that instead of as UA-less.  (nginx's auth_request
	// inherits the client's headers, so there the substitution was invisible.)
	ua := headerOrFallback(r, "X-Original-UA",
		r.Header.Get("X-Original-User-Agent"),
		r.Header.Get("User-Agent"),
	)
	uri := firstNonEmpty(
		r.Header.Get("X-Original-URI"),
		r.URL.RequestURI(),
	)
	host := firstNonEmpty(
		r.Header.Get("X-Original-Host"),
		r.Header.Get("X-Forwarded-Host"),
		r.Host,
	)
	// Header-integrity inputs.  Via the forward-auth subrequest the snippet
	// forwards the original client's values on X-Original-*; on a direct hit
	// (native machinery / a bare curl) fall back to the live request.  A direct
	// request that terminated TLS on this daemon has r.TLS set; behind an LB the
	// snippet's X-Original-Scheme carries the edge scheme.
	secChUA := firstNonEmpty(r.Header.Get("X-Original-Sec-CH-UA"), r.Header.Get("Sec-CH-UA"))
	scheme := firstNonEmpty(r.Header.Get("X-Original-Scheme"), func() string {
		if r.TLS != nil {
			return "https"
		}
		return ""
	}())
	// h2/h3: the snippet forwards nginx's $http2/$http3 (non-empty on those
	// protocols); a direct request exposes it via r.ProtoMajor / Proto.
	modernHTTP := r.Header.Get("X-Original-HTTP2") != "" || r.Header.Get("X-Original-HTTP3") != "" ||
		r.ProtoMajor >= 2
	// Keep the published snapshot POINTER too: it identifies the settings
	// generation and is the bypassMatchers cache key (a value copy's address
	// changes per call and can never hit).
	snap := h.cfg()
	cfg := *snap
	site := siteFromRequest(r, cfg)
	// The old _br cookie (= the previous transient PoW marker) is gone.
	// In the current design, the PoW-passed cookie is the 4-seg _bv
	// ("day.sig.target.flags").  It surfaces in reason as "bv-pow".

	// JA4 fingerprint. An upstream proxy may forward the real client's JA4
	// via X-Client-JA4. Trust is keyed on the connection PEER (= the proxy
	// that called /api/check), never on the resolved visitor IP — the
	// visitor sits behind the proxy and would never match.  The peer must
	// match either loopback (= nginx → admin local hop) or one of the
	// trusted LBs configured for native mode (= nginx.trusted_lb_presets /
	// trusted_lb_extra), so the operator configures the trust list in one
	// place.
	ja4 := resolveForwardedJA4(r, cfg)

	matchers := h.bypassMatchers(snap, site)
	ja4Verdict, ja4Action := matchJA4(ja4, cfg.Nginx)

	// Fail-open defaults: the decision pipeline below reassigns these on every
	// path, but keeping the explicit "pass" leaves the verdict safe if a future
	// axis is ever added without setting them.
	action := "pass"        //nolint:ineffassign // intentional fail-open default
	reason := "ok"          //nolint:ineffassign // intentional fail-open default
	status := http.StatusOK //nolint:ineffassign // intentional fail-open default

	// Web Bot Auth (RFC 9421) is an explicit veto-pass axis: a valid signed
	// request joins the search-bot rescue path instead of running through
	// the score axes.  Verify up-front so the result is available to the
	// switch below + can be logged in the event payload regardless of which
	// axis ended up winning (= operator visibility).
	var wbaResult webbotauth.Result
	if cfg.Nginx.WebBotAuthActive() && h.WebBotAuth != nil && r.Header.Get("Signature-Input") != "" {
		wbaResult = h.WebBotAuth.Verify(r.Context(), wbaVerifyRequest(r))
		if !wbaResult.OK && wbaResult.Reason != "" {
			// A failed verification downgrades silently into the normal axis
			// pipeline, which is the right traffic behavior but hides WHY a
			// signature was rejected — and a misconfigured directory / clock /
			// allowlist looks exactly like a hostile forgery from the outside.
			// Only requests that DID carry a Signature-Input reach here, so
			// this stays quiet for normal traffic.
			log.Printf("unmask: web-bot-auth: signature rejected: %s", wbaResult.Reason)
		}
	}

	// Privacy Pass / PAT (RFC 9577/9578): a second veto-pass axis.  A valid,
	// origin-bound token from a trusted issuer joins the pass path, so an
	// attested real client (e.g. an Apple device presenting a Private Access
	// Token) skips the challenge.  Only requests carrying an
	// "Authorization: PrivateToken" header are touched; everything else is
	// unaffected.  Verified up-front like wbaResult so the switch can use it.
	var patResult privacypass.Result
	if cfg.Nginx.PrivacyPassActive() && h.PrivacyPass != nil {
		if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "PrivateToken") {
			// Bind to requestHost(r): the canonical host source the _bv cookie and
			// the challenge emission also use, so the recomputed challenge digest
			// matches the one the client's token was minted against.
			patResult = h.PrivacyPass.VerifyForOrigin(authz, requestHost(r))
			if !patResult.OK && patResult.Reason != "" {
				// Only requests that DID carry a PrivateToken reach here, so this
				// stays quiet for normal traffic; surfaces a misconfigured issuer
				// key / stale challenge instead of silently downgrading.
				log.Printf("unmask: privacy-pass: token rejected: %s", patResult.Reason)
			}
		}
	}

	// 2. Decision pipeline.
	//
	// Phase A: veto-pass axes.  bypass_ips / bypass_paths / _bv cookie pass
	// are explicit allowlists — they short-circuit before any score axis
	// fires so an operator-trusted client is never re-challenged.
	//
	// Phase B: score axes.  geo / honeypot / ban / protected / ja4 / UA each
	// produces a decision; the strongest severity wins (= "defense in
	// depth": if both geo says pow_only and ja4 says captcha_only, the
	// visitor gets captcha_only).  Side-effects (= honeypot's BAN add) fire
	// inside each axis regardless of whether it wins the max.
	bvCookie, bvCookieKind := pickValidBV(r, cfg, ip, site)
	bvOK := bvCookie != ""
	// honeypotChMode: chain to surface to the challenge JS when the
	// honeypot case takes the challenge branch.  Set by honeypotDecide
	// for the response-header block below.
	honeypotChMode := ""

	// Decision order mirrors native mode's BAN if-block + $final_challenge map:
	//   ban  >  signed_agent / bv / search_bot / bypass_ip / bypass_path  >
	//   geo / protected / ja4 / honeypot / ua
	//
	// (1) BAN is terminal and FIRST.  In native mode the BAN if-block precedes
	// the $final_challenge map, so a banned entity cannot escape via a bv-cookie,
	// a bypass IP/path, or a signed-agent header.  The old forward-auth pipeline
	// put ban in the max-severity group AFTER those veto-passes, letting a banned
	// bot slip through on a bypass path or a still-valid _bv (up to 3 days).
	// rDNS crawler authentication.  It runs ONLY for a crawler-claim NOT already
	// covered by a bypass IP range: for a vendor that publishes ranges (Googlebot,
	// Bingbot) an in-range visitor is authoritatively verified by the range, so
	// rDNS would be a redundant DNS lookup.  rDNS earns its keep off-range -- a
	// range-less crawler (YandexBot/Baiduspider), a range that has drifted, or a
	// forgery claiming a range vendor from outside its range.  The request path
	// only READS the cache (no DNS, no latency); a miss schedules a background
	// check and falls through.  Verified/Forged sit at the top of the veto switch,
	// above the blind UA rescue a forgery must not reach.
	var cvResult crawlerverify.Result
	cvActionable := false
	if claimed := crawlerverify.ClaimedCrawler(ua); h.CrawlerVerify != nil && cfg.Nginx.CrawlerVerify.Enabled &&
		claimed != "" && cfg.Nginx.CrawlerVerify.CrawlerActive(claimed) && !matchers.ipBypass.Match(ip) {
		if res, ok := h.CrawlerVerify.Cached(ip, ua); !ok {
			h.CrawlerVerify.VerifyAsync(ip, ua)
		} else if res.Status == crawlerverify.Verified || res.Status == crawlerverify.Forged {
			cvResult, cvActionable = res, true
		}
	}

	if d, ok := banDecide(r.Context(), h.BanMgr, ip, cfg); ok {
		if d.sev == sevDeny {
			action, reason, status = "block", d.reason, http.StatusForbidden
		} else {
			action, reason, status = "challenge", d.reason, http.StatusUnauthorized
		}
		honeypotChMode = d.chMode
	} else {
		switch {
		// (2a) rDNS crawler verdict — authoritative for a claimed crawler.
		case cvActionable && cvResult.Status == crawlerverify.Verified:
			// A genuine crawler, confirmed against the vendor's rDNS regardless of
			// whether its IP is in a bypass range preset (ranges drift).
			action, reason, status = "pass", "crawler:verified:"+cvResult.Crawler, http.StatusOK
		case cvActionable && cvResult.Status == crawlerverify.Forged:
			// UA claims a crawler but rDNS disproves it: the fake-Googlebot class.
			d := forgedCrawlerDecision(cfg.Nginx.CrawlerVerify, cvResult.Crawler)
			if d.sev == sevDeny {
				action, reason, status = "block", d.reason, http.StatusForbidden
			} else {
				action, reason, status = "challenge", d.reason, http.StatusUnauthorized
			}
			honeypotChMode = d.chMode
		// Hard deny.  Placed with the ban, above everything else, because it is
		// the same kind of statement: the operator said this client is not
		// served, and there is nothing for it to prove otherwise.
		//
		// It has to sit ABOVE the pass cookie (case bvOK below) -- where it used
		// to be, under it, "deny" meant "deny unless you cleared a challenge at
		// some point in the last week", so anything able to clear one met the
		// rule exactly once.  Observed: a crawler already removed from the
		// rescue list solved the proof-of-work across its whole address pool
		// and then took as much as it wanted for a day.
		//
		// It also has to sit above the Web Bot Auth and Privacy Pass vetoes,
		// because native does: server.inc dispatches $unmask_deny_now before
		// either gate, so with this case below them a signed agent whose UA is
		// denied would be blocked in native mode and passed in forward-auth.
		// (Above them is also the cheaper order -- verifying a signature we are
		// about to discard costs a subrequest to the daemon.)
		//
		// The rescues are re-checked here rather than left to the cases below,
		// because those come after the cookie: a search bot or a bypassed
		// address must still pass.  Same set native folds into $unmask_deny_now.
		case hardDenyUA(ua, cfg.Nginx) &&
			!isSearchBotUA(ua, ja4Action, cfg.Nginx, matchers.rangeVerifiedUA) &&
			!matchers.ipBypass.Match(ip) && !matchPath(uri, matchers.bypass):
			action, reason, status = "block", "ua:deny", http.StatusForbidden
		// (2) Veto-passes, in native order.  Each is a hard pass that wins over
		// the gating axes below.
		case wbaResult.OK && cfg.Nginx.WebBotAuth.IsOperatorAllowed(wbaResult.Operator):
			// Signed agent verified — same trust level as the IP allowlist.
			// Reason carries the operator host so dashboards can break it down.
			action, reason, status = "pass", "signed_agent:"+wbaResult.Operator, http.StatusOK
		case patResult.OK:
			// Attested real client (Privacy Pass / PAT): an origin-bound token
			// from a trusted issuer.  Reason carries the issuer for dashboards.
			action, reason, status = "pass", "privacy_pass:"+patResult.Issuer, http.StatusOK
		case bvOK && !(!gradeSatisfies(bvCookieKind) &&
			(requestNeedsCaptchaGrade(ua, uri, site, cfg) ||
				h.axisNeedsCaptchaGradeFor(ip, uri, matchers, cfg))):
			// Named after the entry that verified (see pickValidBV): a PoW
			// solve, a CAPTCHA solve, or a credential re-bound onto this
			// address after a solve elsewhere.  A PoW cookie does NOT pass here
			// when the UA's chain, the protected path it hit, or its network's
			// geo/ASN rule ends in a CAPTCHA — it falls through to the gating
			// axes, which re-issue the right challenge.  Grade first: a
			// CAPTCHA-grade cookie satisfies every source, so the common
			// repeat-visitor case skips both the UA scan and the mmdb lookup.
			action, reason, status = "pass", "bv-"+bvCookieKind, http.StatusOK
		case isSearchBotUA(ua, ja4Action, cfg.Nginx, matchers.rangeVerifiedUA):
			// Search / AI crawler rescue.  Must win over geo / protected / ja4 /
			// honeypot exactly like native's is_search_bot exemption, else
			// crawlers without an IP-range preset (ClaudeBot / YandexBot /
			// Bytespider) get wrongly blocked = the ranking accident this
			// project exists to prevent.  Range-verified vendors (Googlebot,
			// bingbot, GPTBot, ...) are excluded from the UA rescue here and
			// pass via the bypass-IP veto below instead (see uarange.go).
			action, reason, status = "pass", "ua:search_ai", http.StatusOK
		case notifPreviewRescue(ua, ja4, matchers):
			// Guarded notification-preview rescue: the UA must be backed by
			// Apple's TLS stack (JA4_b cipher hash), mirroring native's
			// "$unmask_notif_preview_ua$unmask_apple_tls" composite.  These
			// fetchers run on subscribers' own devices (residential IPs, no
			// vendor ranges), so a UA-only rescue would be one copied header
			// line away from every scraper; a JA4 that is absent (no TLS /
			// LB that hides the client hello) or non-Apple falls through to
			// the ordinary challenge flow.
			action, reason, status = "pass", "ua:search_ai", http.StatusOK
		case matchers.ipBypass.Match(ip):
			action, reason, status = "pass", "bypass:ip", http.StatusOK
		case matchPath(uri, matchers.bypass):
			action, reason, status = "pass", "bypass:path", http.StatusOK
		default:
			// (3) Gating axes: collect, take max severity (ban already handled).
			decisions := make([]axisDecision, 0, 7)
			// Community feed first: on a severity tie its reason is the most
			// specific one an operator can act on ("this client is on the
			// shared list"), so it should be the story the event tells rather
			// than a generic geo / UA label.
			if d, ok := communityBansDecide(h.communityBansMatcher(), ip, ja4, cfg); ok {
				decisions = append(decisions, d)
			}
			// Per-axis exempt paths (RSS/Atom feeds etc.): each skips ONLY its
			// own axis; honeypot / protected / ja4 / ua below still run.  (A
			// full pass is bypass:path, in the veto switch before this case.)
			if !matchPath(uri, matchers.geoExempt) {
				if d, ok := h.geoDecide(ip, cfg); ok {
					decisions = append(decisions, d)
				}
			}
			if !matchPath(uri, matchers.asnExempt) {
				if d, ok := h.asnDecide(ip, cfg); ok {
					decisions = append(decisions, d)
				}
			}
			if d, ok := honeypotDecide(r.Context(), uri, matchers, cfg, h.BanMgr, ip, host); ok {
				decisions = append(decisions, d)
			}
			if d, ok := protectedDecide(uri, matchers, cfg, site); ok {
				decisions = append(decisions, d)
			}
			if d, ok := ja4Decide(ja4Action, ja4Verdict, cfg.Nginx); ok {
				decisions = append(decisions, d)
			}
			// Header integrity is listed BEFORE the UA axis.  pickStrongest
			// keeps the first decision at the winning severity, and the two
			// default to the same action (captcha_only) -- so with both firing
			// the later one used to be reported as the reason.  The UA axis is
			// where the stale-browser tier lives, which meant a stale Chromium
			// missing its client hints was attributed to "stale" here while
			// the native path attributed the same request to "header": one
			// visitor, two different stories depending on deploy mode.  Header
			// integrity is the sharper signal of the two (a browser's own
			// headers contradict its UA), so it wins the tie in both modes.
			// A genuinely stronger UA action still wins on severity.
			if d, ok := headerDecide(ua, secChUA, scheme, modernHTTP, cfg.Global); ok {
				decisions = append(decisions, d)
			}
			if d, ok := uaDecide(ua, ja4Action, cfg, matchers.rangeVerifiedUA); ok {
				decisions = append(decisions, d)
			}
			winner, suppressed := pickStrongest(decisions)
			switch winner.sev {
			case sevPass:
				// No axis voted to challenge — let through.  Reason picks the
				// most-informative passive label (= UA classify if it ran).
				action, reason, status = "pass", "ok", http.StatusOK
				for _, d := range decisions {
					if d.reason != "" && d.sev == sevPass {
						reason = d.reason
						break
					}
				}
			case sevDeny:
				action, reason, status = "block", winner.reason, http.StatusForbidden
			default:
				action, reason, status = "challenge", winner.reason, http.StatusUnauthorized
			}
			// honeypot's chMode flows through the X-Unmask-Chmode response header
			// so the challenge HTML knows which chain to run.
			if winner.chMode != "" {
				honeypotChMode = winner.chMode
			}
			// Attach suppressed-reason trail for transparency (audit / hunt).
			if len(suppressed) > 0 {
				reason = reason + " (suppressed: " + strings.Join(suppressed, ", ") + ")"
			}
		}
	}

	// 2.5. rate-limit.  Don't count requests already decided by bypass /
	// cookie pass / honeypot / ban (= respect existing fast path /
	// final block).  Otherwise count, and on threshold exceedance,
	// promote to challenge + emit the zone / challenge_mode in response
	// headers so nginx can transfer them into the error_page query.
	// Every zone that applies to this request counts in parallel -- custom
	// zones in config order plus the default -- exactly as native mode stacks
	// one limit_req per zone.  (This used to be first-match-only, which
	// diverged from native whenever two zones overlapped: an all-paths JA4
	// zone would have silently replaced the per-IP default here while native
	// enforced both.)
	rlZones := cfg.RateLimit.ResolveZonesAll(uri, site)
	// zone / chMode: the row a trip is attributed to.  Until something trips
	// they describe the first (= most specific) row, so payloads and headers
	// keep their pre-multi-zone meaning.
	zone := rlZones[len(rlZones)-1].RateLimitValues
	if len(rlZones) > 1 {
		zone = rlZones[0].RateLimitValues
	}
	chMode := zone.ResolvedChallengeMode()
	rlHit := false
	rlCount := 0
	rlAllowance := 0
	// Trusted sources are exempt from every zone kind.  The _bv exemption is
	// per-zone below: a valid _bv (already passed a challenge) skips
	// CHALLENGE-mode zones -- re-challenging someone who just proved human is
	// pointless -- but a "deny" zone is a HARD CAP and counts _bv holders,
	// who must not buy a pass past it by flooding.
	shouldCount := h.RateLimiter != nil &&
		reason != "bypass:ip" &&
		reason != "bypass:path" &&
		reason != "ua:search_ai" && // never rate-limit rescued crawlers (= ranking accidents on large crawls; mirrors native's empty $rate_limit_key for is_search_bot)
		!strings.HasPrefix(reason, "crawler:verified") && // rDNS-verified crawlers are as trusted as a bypass IP

		!strings.HasPrefix(reason, "signed_agent:") && // verified Web Bot Auth agents aren't rate-limited
		!strings.HasPrefix(reason, "privacy_pass:") && // attested PAT clients aren't rate-limited
		action != "block"
	if shouldCount {
		bvPass := strings.HasPrefix(reason, "bv-")
		denyTripped := false
		for _, z := range rlZones {
			zMode := z.ResolvedChallengeMode()
			if bvPass && zMode != settings.RateChallengeDeny {
				continue
			}
			// Counter key: the zone's resolved key kind -- mirrors the
			// per-zone $rate_limit_key* variant native renders, so a request
			// is counted the same way regardless of deploy mode.
			var keyBase string
			switch z.Key {
			case settings.RateLimitKeyJA4:
				keyBase = ja4
			case settings.RateLimitKeyIPAndJA4:
				keyBase = ip + "|" + ja4
			default:
				keyBase = ip
			}
			res := h.RateLimiter.Hit(keyBase+"|"+z.Name, ratelimit.Spec{
				RequestsPerMin: z.RequestsPerMin,
				Burst:          z.Burst,
				WindowSec:      z.ResolvedWindowSec(),
			})
			if !res.Hit {
				continue
			}
			// First trip wins the attribution (zones are ordered most-specific
			// first), except that a deny trip always takes over: a hard cap
			// must not be reported -- or enforced -- as a recoverable
			// challenge just because a challenge zone tripped first.
			if !rlHit || (zMode == settings.RateChallengeDeny && !denyTripped) {
				zone = z.RateLimitValues
				chMode = zMode
				rlCount = res.Count
				rlAllowance = res.Allowance
			}
			rlHit = true
			denyTripped = denyTripped || zMode == settings.RateChallengeDeny
		}
		if rlHit {
			// challenge mode = "deny" -> skip the challenge and 403 immediately.
			// Use case for API / known-bot paths where "human check unnecessary."
			if chMode == settings.RateChallengeDeny {
				action = "block"
				status = http.StatusForbidden
			} else if action == "pass" {
				// What was pass / human is promoted to challenge.
				action = "challenge"
				status = http.StatusUnauthorized
			}
			// Already challenge / block -> keep that status and append rl info to reason.
			if reason != "" && !strings.HasPrefix(reason, "ratelimit") {
				reason = "ratelimit:" + zone.Name + " (was:" + reason + ")"
			} else {
				reason = "ratelimit:" + zone.Name
			}
		}
	}

	// 2.7. monitor mode (= ObserveOnly).  Suppress every challenge /
	// block and return pass, but keep recording events + dashboard
	// stats unchanged.  Used as the preview during the observation
	// phase right after install, to see "how many challenges would
	// fire if I went strict."  The original action is saved in
	// payload.would_be_action.
	observeOnly := cfg.Challenge.Resolve(site).IsObserveOnly() && (action == "challenge" || action == "block")
	wouldBeAction := action
	wouldBeReason := reason

	// 3. Record the event (= flow into dashboard / bot-hunt tab).
	// Insert with phase=check for every action.  In forward-auth mode
	// "every request must be visible" is an operational requirement,
	// so leave a check event even for challenge.  In native mode
	// AuthCheck itself is not called so there's no duplicate
	// (= ServeChallenge inserts a serve event under a different phase,
	// coexisting cleanly).
	if pkt := events.PackIP(ip); pkt != nil {
		payload := map[string]any{
			"action": action,
			"reason": reason,
			"uri":    truncateAt(uri, 200),
			"host":   truncateAt(host, 100),
		}
		if observeOnly {
			payload["observe_only"] = 1
			payload["would_be_action"] = wouldBeAction
			payload["would_be_reason"] = wouldBeReason
		}
		if rlHit {
			payload["rl"] = 1
			payload["rl_zone"] = zone.Name
			payload["rl_count"] = rlCount
			payload["rl_allowance"] = rlAllowance
			payload["rl_chmode"] = chMode
		}
		if lbWarn := detectLBHeaderWarning(r, cfg); lbWarn != "" {
			payload["lb_warning"] = lbWarn
		}
		// referer of the original request (forward-auth sees it per-request, so a
		// PASS carries where the human came from -- the native wire's pass never
		// reaches the daemon).  Display-only; often empty.
		if refr := refererForEvent(r); refr != "" {
			payload["referer"] = refr
		}
		// local_port: only when an LB made the client-facing port an inference
		// (see localPortNote).  Absent on every unproxied install.
		if lp := localPortNote(r, portFromRequest(r)); lp > 0 {
			payload["local_port"] = lp
		}
		events.InsertAsync(h.DB, &events.Event{
			Site:         site,
			Host:         h.HostID,
			IPPacked:     pkt,
			UserAgent:    ua,
			JA4:          ja4,
			JA4Verdict:   ja4Verdict,
			JA4VerdictID: h.VerdictNameToID(ja4Verdict),
			Phase:        "check",
			Payload:      payload,
		})
	}

	// Bump the cookie-pass-rate chart (= unmask_cookie_minute, kind/cnt normalized) by 1.
	// kind values:
	//   "captcha"          : reason="bv-captcha" (= 3-seg _bv HMAC OK, solved)
	//   "rebind"           : reason="bv-rebind"  (= 3-seg _bv HMAC OK, roamed)
	//   "pow"              : reason="bv-pow"     (= 4-seg _bv SHA-256 OK)
	//   "challenge_served" : action=challenge or block
	//   ""                 : no signals tripped, total only +1
	if h.NginxLog != nil {
		// bvKind is the RAW _bv kind ("captcha"/"pow"/""), before the
		// challenge_served alias -- the HLL pass bucket counts only a genuine
		// cookie, so it must not see the alias.
		bvKind := ""
		if action == "pass" && strings.HasPrefix(reason, "bv-") {
			bvKind = bvCookieKind
		}
		kind := bvKind
		if kind == "" && (action == "challenge" || action == "block") {
			kind = "challenge_served"
		}
		fc := action == "challenge" || action == "block"
		h.NginxLog.Bump(site, kind)
		// In forward-auth mode no access-log line is emitted, so feed the same
		// aggregates onLine() fills in native mode -- otherwise the crawler
		// funnel, unique-IP (DailyUniqueIPs) and per-country (DailyPassByCountry)
		// charts are blank in forward-auth.
		h.NginxLog.BumpCrawler(ua, action != "pass")
		// The same classification onLine performs natively, in the same order:
		// pass cookie, then challenged, then listed crawler, then bypassed.
		// Exactly one may fire, because all four are shares of the one total the
		// composition card divides up -- counting a cookie holder twice steals
		// from the human remainder, which on an install serving its own assets
		// from bypassed paths is a large share of the total.
		//
		// The crawler arm was absent here, and only this wire can lose it:
		// native reads the classification off the log line, forward-auth has to
		// state it.  Every rescued crawler therefore fell out of the benign
		// share into the residue, which is how it was found -- the residue
		// tracked the crawler table request for request (227 of 1,094 in an
		// hour) while crawler_pass stayed at zero all day.
		switch {
		case bvKind != "" || fc:
			// counted by Bump above as pow / captcha / challenge_served.
		case classify.LookupTag(ua) != "":
			h.NginxLog.BumpCrawlerPass(site)
		case reason == "bypass:ip" || reason == "bypass:path":
			h.NginxLog.BumpBypass(site)
		}
		h.NginxLog.BumpTrafficHLL(site, ip, fc, bvKind, ua)
		h.NginxLog.BumpCountry(site, ip, kind)
		// Per-IP cookie-reuse ranking.  Pass the raw bvKind (not the
		// challenge_served alias) so only a genuinely reused cookie is counted;
		// bumpCookieIP no-ops unless bvKind is "captcha" or "pow".
		h.NginxLog.BumpCookieIP(site, ip, ja4, ua, bvKind)
	}

	// 2.8. monitor mode override (= switch right before responding, after
	// stats / nginxlog bump are recorded with the original action).
	// That way the dashboard keeps showing "the challenge count we'd
	// get if we went strict," while nginx receives pass.
	if observeOnly {
		action = "pass"
		status = http.StatusOK
		reason = "observe_only (was:" + wouldBeReason + ")"
		rlHit = false
	}

	// 4. Response headers + status.
	w.Header().Set("X-Unmask-Action", action)
	w.Header().Set("X-Unmask-Reason", reason)
	// When promoted to challenge via rate-limit, nginx pulls them into
	// variables via `auth_request_set $unmask_zone` +
	// `auth_request_set $unmask_chmode` and forwards them in the
	// error_page 401 redirect query (= ?rl=<zone>&chm=<mode>) for the
	// challenge handler to read.
	if rlHit {
		w.Header().Set("X-Unmask-Zone", zone.Name)
		w.Header().Set("X-Unmask-Chmode", chMode)
	} else if honeypotChMode != "" && action == "challenge" {
		// honeypot took the challenge branch — propagate the chosen
		// chain to /unmask/challenge/ via the same header flow that
		// rate-limit uses (= auth_request_set + ?chm= query).
		w.Header().Set("X-Unmask-Chmode", honeypotChMode)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(action + "\n"))
}

// --- axis decide helpers (= one per scoring axis) ---
//
// Each returns (decision, true) when it has an opinion, or (zero, false)
// when silent.  The AuthCheck pipeline collects them into a slice and
// pickStrongest picks the harshest severity.  Side-effects (= honeypot's
// BAN add) run inside the helper so they fire regardless of who wins.

// geoDecide consults settings.Nginx.Geo for the visitor's country.  Country
// resolution (= mmdb lookup) and the per-country policy decision are split
// so the latter can be table-tested.
// forgedCrawlerDecision maps the operator's ForgedAction to a decision, reusing
// the shared severity/chMode mapping so a forged crawler challenges (or denies)
// exactly like the gating axes.
func forgedCrawlerDecision(cfg settings.CrawlerVerifyConfig, crawler string) axisDecision {
	reason := "crawler:forged:" + crawler
	act := cfg.ResolvedForgedAction()
	if act == settings.GeoActionDeny {
		return axisDecision{sev: sevDeny, reason: reason}
	}
	s := severityFromAction(act)
	return axisDecision{sev: s, reason: reason, chMode: chModeFromSeverity(s)}
}

func (h *Handler) geoDecide(ip string, cfg settings.Settings) (axisDecision, bool) {
	if h.IPGeo == nil || !h.IPGeo.Loaded() {
		return axisDecision{}, false
	}
	country := strings.ToUpper(strings.TrimSpace(h.IPGeo.LookupInfo(ip).Country))
	d, rate, ok := geoDecideForCountry(country, cfg.Nginx.Geo)
	if !ok {
		return axisDecision{}, false
	}
	// rate>0 throttles the country to N req/min (one shared counter per
	// country); the action fires only on the overage -- the by-country twin
	// of the ASN rate path.
	return applyNetRate(d, "geo:"+country, rate, h.RateLimiter)
}

// geoDecideForCountry: pure decision given a resolved country string.
//   - empty country -> silent (= mmdb miss / private IP, fail-open)
//   - resolved action "skip" or empty -> silent (= geo intentionally
//     declines to act for this country; lets other axes decide)
//   - "deny" -> sevDeny
//   - challenge-mode action -> matching severity, chMode set
//
// A REGISTERED country with a blank action inherits DefaultRuleAction (a
// registered row exists to act); only an unmatched country falls to
// DefaultAction.  rate is the matched rule's effective RatePerMin (0 for an
// unmatched country -- the default action is never throttled).
func geoDecideForCountry(country string, geo settings.GeoConfig) (d axisDecision, rate int, ok bool) {
	if country == "" {
		return axisDecision{}, 0, false
	}
	act := geo.ResolvedDefaultAction()
	if rule := geo.LookupRule(country); rule != nil {
		act = rule.Action
		if strings.TrimSpace(act) == "" {
			act = geo.ResolvedDefaultRuleAction()
		}
		rate = geo.EffectiveRatePerMin(rule.RatePerMin)
	}
	switch act {
	case "", settings.GeoActionSkip:
		return axisDecision{}, 0, false
	case settings.GeoActionDeny:
		return axisDecision{sev: sevDeny, reason: "geo:" + country + ":deny"}, rate, true
	default:
		s := severityFromAction(act)
		return axisDecision{sev: s, reason: "geo:" + country + ":" + act, chMode: chModeFromSeverity(s)}, rate, true
	}
}

// asnDecide consults settings.Nginx.Asn for the visitor's autonomous system.
// The by-network sibling of geoDecide: same lookup source (the ASN mmdb via
// IPGeo), same decision machinery.  Matches on the exact AS number and the
// organization name (so a "Microsoft" org rule / the Microsoft catalog
// provider covers all of Azure's ASNs).  Inert when no ASN db is loaded.
func (h *Handler) asnDecide(ip string, cfg settings.Settings) (axisDecision, bool) {
	if h.IPGeo == nil || !h.IPGeo.ASNLoaded() {
		return axisDecision{}, false
	}
	info := h.IPGeo.LookupInfo(ip)
	d, netKey, rate, ok := asnResolve(info.ASN, info.ASNOrg, cfg.Nginx.Asn)
	if !ok {
		return axisDecision{}, false
	}
	return applyNetRate(d, netKey, rate, h.RateLimiter)
}

// applyNetRate turns a network-axis (asn/geo) action decision into its
// rate-limited form.  rate<=0
// -> the action applies to every request (return d unchanged).  rate>0 -> the
// matched AS number is throttled to `rate` req/min (one shared counter); the
// action fires only on the overage, and stays silent under the cap.  A nil
// limiter can't count, so it fails open (silent).
// netRateOverageAction resolves the action a native rate-limit OVERAGE should
// serve for a client, re-deriving its ASN / country from the IP (native only
// carries "you hit a rate zone", not which rule).  It answers the ASN/geo
// per-rule action when the client matches a rate-mode rule, else "".  Exact-AS
// / org rules win over the country rule when both match (ASN is the more
// specific network signal), matching the max-specificity intent -- but note
// the caller only reaches here on an overage, so either rule firing is enough.
func (h *Handler) netRateOverageAction(ip string, cfg settings.Settings) string {
	if h.IPGeo == nil || ip == "" {
		return ""
	}
	info := h.IPGeo.LookupInfo(ip)
	// ASN first (more specific).
	if h.IPGeo.ASNLoaded() {
		for _, rr := range cfg.Nginx.Asn.RateRules() {
			if (rr.ASN != 0 && info.ASN == rr.ASN) ||
				(rr.ASN == 0 && rr.Org != "" && settings.OrgMatchesAny(info.ASNOrg, []string{rr.Org})) {
				return rr.Action
			}
		}
	}
	if h.IPGeo.Loaded() {
		cc := strings.ToUpper(strings.TrimSpace(info.Country))
		for _, rr := range cfg.Nginx.Geo.RateRules() {
			if rr.Country == cc {
				return rr.Action
			}
		}
	}
	return ""
}

func applyNetRate(d axisDecision, netKey string, rate int, rl *ratelimit.Limiter) (axisDecision, bool) {
	if rate <= 0 {
		return d, true
	}
	if rl == nil {
		return axisDecision{}, false
	}
	if !rl.Hit("netrate|"+netKey, ratelimit.Spec{RequestsPerMin: rate, WindowSec: 60}).Hit {
		return axisDecision{}, false // under the cap -> pass
	}
	d.reason = netKey + ":rate>" + strconv.Itoa(rate) + strings.TrimPrefix(d.reason, netKey)
	return d, true
}

// asnResolve is the pure ASN resolution: the matched rule/provider -> an action
// decision, plus the network key (per-AS-number counter) and the rule's
// RatePerMin.  netKey is "asn:AS<n>" (or "asn:<org>" when the AS number is
// unknown).
//   - no match / action skip|empty -> silent
//   - deny -> sevDeny ; challenge-mode action -> matching severity + chMode
func asnResolve(asn uint, org string, cfg settings.AsnConfig) (d axisDecision, netKey string, rate int, ok bool) {
	if asn == 0 && org == "" {
		return axisDecision{}, "", 0, false
	}
	act, r, matched := cfg.ResolveRule(asn, org)
	if !matched {
		return axisDecision{}, "", 0, false
	}
	netKey = "asn:"
	if asn != 0 {
		netKey += "AS" + strconv.FormatUint(uint64(asn), 10)
	} else {
		netKey += org
	}
	switch act {
	case "", settings.GeoActionSkip:
		return axisDecision{}, "", 0, false
	case settings.GeoActionDeny:
		return axisDecision{sev: sevDeny, reason: netKey + ":deny"}, netKey, r, true
	default:
		s := severityFromAction(act)
		return axisDecision{sev: s, reason: netKey + ":" + act, chMode: chModeFromSeverity(s)}, netKey, r, true
	}
}

// asnDecideFor is the immediate action decision (rate ignored), retained for the
// unit test and any caller that only needs the per-request verdict.
func asnDecideFor(asn uint, org string, cfg settings.AsnConfig) (axisDecision, bool) {
	d, _, _, ok := asnResolve(asn, org, cfg)
	return d, ok
}

// honeypotDecide returns a decision when the URI matches a honeypot path.
// Side effect: adds an entry to the persistent BAN list (= regardless of
// whether honeypot wins the max — the trap counts even if a stronger axis
// is the visible verdict).
func honeypotDecide(ctx context.Context, uri string, matchers pathMatchers, cfg settings.Settings,
	banMgr *ban.Manager, ip, host string) (axisDecision, bool) {
	presetAct, ok := matchHoneypot(uri, matchers.honeypot)
	if !ok {
		return axisDecision{}, false
	}
	if banMgr != nil {
		// Persist the RAW per-preset/per-URL override ("" = inherit) as the ban's
		// action column so every subsequent request -- native (ban-file read) and
		// forward-auth (banDecide rowAction) alike -- enforces the operator's
		// per-preset choice, not just this first trip.
		banMgr.AddWithSourceAction(ctx, ip, "", "honeypot",
			"auth_request: "+honeypotReason(host, uri), "", presetAct)
	}
	// Immediate decision: per-preset override -> Honeypot.DefaultAction -> the
	// same rate-limit chain default the other axes inherit.  A per-preset
	// captcha_only lets the operator make a high-risk trap demand the harder
	// (bot-filtering) challenge while everything else stays on the global default.
	act := strings.TrimSpace(presetAct)
	if act == "" {
		act = strings.TrimSpace(cfg.Nginx.Honeypot.DefaultAction)
	}
	if act == settings.RateChallengeDeny {
		return axisDecision{sev: sevDeny, reason: "honeypot:deny"}, true
	}
	if !settings.IsValidRateChallengeMode(act) {
		act = settings.RateChallengePoWThenCaptcha
	}
	s := severityFromAction(act)
	return axisDecision{sev: s, reason: "honeypot:" + act, chMode: chModeFromSeverity(s)}, true
}

// HoneypotReason writes the ban reason for a honeypot trip: which host was
// probed and which trap fired.  One function for both wires, because a reason
// is what the operator reads months later and two spellings of the same event
// read as two different events.
//
// The host leads because on a multi-site install a path alone does not say
// whose trap this was -- /cgi-bin/ exists on every vhost that has one, and
// "which site is being scanned" is usually the first question.  It is the
// request's own Host, so it is attacker-supplied like the path; both are
// truncated and neither is interpreted.
//
// honeypotReason is the unexported spelling used inside this package; the
// exported one exists for the native wire, which builds the same reason from
// an access-log line in main.go.
func HoneypotReason(host, uri string) string { return honeypotReason(host, uri) }

// reasonMaxLen mirrors the reason column (VARCHAR(255) on both backends).  The
// parts are budgeted to fit rather than trimmed afterwards, so a scanner
// sending a kilobyte of path cannot decide how much of the host survives --
// the host is the half that answers "which site", and it is never the part
// that gets cut.
const (
	reasonMaxLen  = 255
	reasonHostMax = 60
	reasonURIMax  = 180 // 4 ("hit ") + 60 + 180 = 244
)

func honeypotReason(host, uri string) string {
	uri = truncateAt(strings.TrimSpace(uri), reasonURIMax)
	host = truncateAt(strings.TrimSpace(host), reasonHostMax)
	if uri == "" {
		// Nothing to name.  "honeypot" alone is what the column said before a
		// trip carried its URL, and it stays truthful when one does not.
		if host == "" {
			return "honeypot"
		}
		return "honeypot on " + host
	}
	if host == "" {
		return "hit " + uri
	}
	return "hit " + host + uri
}

// matchHoneypot returns the action override of the FIRST honeypot rule uri hits.
// action=="" = inherit Honeypot.DefaultAction; ok=false = no honeypot rule hit.
func matchHoneypot(uri string, list []honeypotRule) (action string, ok bool) {
	for _, h := range list {
		if h.re.MatchString(uri) {
			return h.action, true
		}
	}
	return "", false
}

// banDecide consults the persistent BAN list.  Resolution (= mgr lookup) is
// split from the per-source policy so the policy half is table-testable.
func banDecide(ctx context.Context, mgr *ban.Manager, ip string, cfg settings.Settings) (axisDecision, bool) {
	if mgr == nil {
		return axisDecision{}, false
	}
	rowAction, src, banned := mgr.IsBannedActionSource(ctx, ip, "")
	if !banned {
		return axisDecision{}, false
	}
	return banDecideFromSource(rowAction, src, cfg)
}

// banDecideFromSource: pure decision given a ban source string.  Each
// source (= "honeypot" / "manual" / "community_bans") picks its action from
// settings via BansConfig.ResolveAction (= honeypot defers to
// Honeypot.DefaultAction; the others read Bans.ManualDefaultAction /
// Bans.CommunityBansDefaultAction).  Unknown sources hard-deny so a future
// source never silently falls through.
func banDecideFromSource(rowAction, src string, cfg settings.Settings) (axisDecision, bool) {
	// A per-row action override (e.g. a manual ban explicitly set to "deny" in
	// the UI) wins over the source's default -- the same precedence native bakes
	// into the ban file via Manager.EffectiveAction.  Empty -> the source default.
	act := strings.TrimSpace(rowAction)
	if act == "" {
		act = cfg.Nginx.Bans.ResolveAction(src, cfg.Nginx.Honeypot.DefaultAction)
	}
	if act == settings.RateChallengeDeny {
		return axisDecision{sev: sevDeny, reason: "ban:" + src + ":deny"}, true
	}
	if !settings.IsValidRateChallengeMode(act) {
		// Mirror honeypotDecide -- inherit the rate-limit chain default.
		act = settings.RateChallengePoWThenCaptcha
	}
	s := severityFromAction(act)
	return axisDecision{sev: s, reason: "ban:" + src + ":" + act, chMode: chModeFromSeverity(s)}, true
}

// protectedDecide fires when the URI matches a protected-paths regex.  Mode ==
// action: the matched path's own mode (pow / captcha / pow_then_captcha, with a
// preset-level override honored) picks the chain directly — no rate-limit
// linkage.  A captcha-ending mode also drives the grade requirement in the
// pass-cookie veto above (requestNeedsCaptchaGrade), so this axis only has to
// state the chain to serve; it never denies.
func protectedDecide(uri string, matchers pathMatchers, cfg settings.Settings, site string) (axisDecision, bool) {
	if !matchPath(uri, matchers.protected) {
		return axisDecision{}, false
	}
	chMode := nginxconf.ChModeForProtectedMode(protectedModeForOrig(cfg.Nginx, site, uri))
	return axisDecision{sev: severityFromAction(chMode), reason: "protected-path", chMode: chMode}, true
}

// headerDecide fires the header-integrity axis: a UA advertising a
// Chromium-family browser, over HTTPS on h2/h3, that carries no Sec-CH-UA is a
// spoof tell (a real Chromium sends client hints in that context).  All four
// preconditions must hold -- anything failing one is silent, which is the
// structural FP fence: the axis never fires on the populations that
// legitimately lack the header (HTTP, HTTP/1.1, Firefox/Safari, TLS-intercept
// proxies over http).  Severity is clamped to the operator's action, which is
// itself clamped to pow/captcha (never deny) by HeaderIntegrityResolvedAction.
func headerDecide(ua, secChUA, scheme string, modernHTTP bool, g settings.GlobalConfig) (axisDecision, bool) {
	if !g.HeaderIntegrity {
		return axisDecision{}, false
	}
	major := classify.ChromeMajor(ua)
	if major == 0 { // not Chromium-family -> no opinion
		return axisDecision{}, false
	}
	if major < classify.SecCHUAMinChromeMajor {
		// Chromium only started sending Sec-CH-UA in 89; on anything older its
		// absence is the norm, not a contradiction.  Without this fence the axis
		// challenged every genuine old browser (an aging Android WebView, a
		// pinned kiosk build) for a header it never had.  A valid _bv cookie is a
		// Phase A veto-pass, so clearing the challenge did buy the usual cookie
		// lifetime -- this was not a permanent lockout.  What made it worse than
		// an ordinary false positive is that the tell is a permanent property of
		// the browser: the same visitor was asked again every time the cookie
		// lapsed, for as long as they kept that device, and the behavioural
		// CAPTCHA is hardest to clear on exactly the old touch handsets this
		// caught.  Observed in the wild as challenge -> challenge -> abandon.
		return axisDecision{}, false
	}
	if scheme != "https" || !modernHTTP {
		return axisDecision{}, false // no secure/modern context -> CH legitimately absent
	}
	if strings.TrimSpace(secChUA) != "" {
		return axisDecision{}, false // the header is present -> consistent
	}
	act := g.HeaderIntegrityResolvedAction()
	s := severityFromAction(act)
	return axisDecision{sev: s, reason: "header:no_sch_ua", chMode: chModeFromSeverity(s)}, true
}

// headerDecideForServe runs the header-integrity axis against a challenge-serve
// request: native reads the live headers, forward-auth the X-Original-* mirror
// the snippet forwards.  Shared by ServeChallenge's force_reason attribution
// and its chMode resolution so the two never drift.
func headerDecideForServe(r *http.Request, g settings.GlobalConfig) (axisDecision, bool) {
	ua := firstNonEmpty(r.Header.Get("X-Original-UA"), r.Header.Get("User-Agent"))
	secChUA := firstNonEmpty(r.Header.Get("X-Original-Sec-CH-UA"), r.Header.Get("Sec-CH-UA"))
	// Prefer the forwarded scheme: behind a TLS-terminating LB the direct
	// r.TLS / r.ProtoMajor describe the LB->daemon hop (plain http/1.1), not the
	// visitor.  X-Original-Scheme (forward-auth snippet) or X-Forwarded-Proto
	// (the LB) carries the visitor's real scheme.
	xfProto := firstNonEmpty(r.Header.Get("X-Original-Scheme"), r.Header.Get("X-Forwarded-Proto"))
	scheme := xfProto
	if scheme == "" && r.TLS != nil {
		scheme = "https"
	}
	// A forwarded request (any X-Forwarded-Proto / X-Original-Scheme present)
	// came through an LB that masks the client's HTTP version, so treat it as a
	// modern context -- a real Chromium over https still sends Sec-CH-UA
	// regardless of h1/h2.  A direct hit uses the real negotiated protocol.
	modern := xfProto != "" || r.Header.Get("X-Original-HTTP2") != "" || r.Header.Get("X-Original-HTTP3") != "" || r.ProtoMajor >= 2
	return headerDecide(ua, secChUA, scheme, modern, g)
}

// headerAxisFiresForServe reports whether the header-integrity axis escalated
// this challenge serve.  Native mode trusts the nginx-computed X-Header-Mismatch
// signal (the map is LB-aware and unspoofable -- proxy_set_header overwrites any
// client-supplied value); forward-auth, whose daemon sees the real request,
// re-derives via headerDecideForServe.  Off when the axis is disabled.
func headerAxisFiresForServe(r *http.Request, g settings.GlobalConfig) bool {
	if !g.HeaderIntegrity {
		return false
	}
	if r.Header.Get("X-Header-Mismatch") == "1" {
		return true
	}
	_, ok := headerDecideForServe(r, g)
	return ok
}

// staleBrowserFiresForServe reports whether the stale-browser tier would escalate
// this challenge-serve request: the axis is on and the UA is pinned to an
// outdated Chrome / Firefox major.  Mirrors the auth_check stale tier so the
// force_reason="stale" attribution never drifts from the actual decision.
func staleBrowserFiresForServe(r *http.Request, g settings.GlobalConfig) bool {
	if !g.StaleBrowserEnabled() {
		return false
	}
	ua := firstNonEmpty(r.Header.Get("X-Original-UA"), r.Header.Get("User-Agent"))
	return classify.IsStaleBrowser(ua, g.CurrentChromeMajorResolved(), g.CurrentFirefoxMajorResolved(),
		g.FirefoxESRMajors(), g.StaleBrowserLagN(), g.FirefoxStaleLagN())
}

// netChallengeReason attributes a network-axis challenge serve to "asn" or
// "geo" when the client's ASN / country matches a *direct* (non-rate) challenge
// rule -- ASN wins over country, mirroring the decision order.  A rate-gated
// rule (rate>0) serves through the rate-limit path (force_reason="rate_limit"),
// so those matches are left for that bucket.  Side-effect-free (no rate-limiter
// Hit): it uses the pure resolvers, not asnDecide/geoDecide.
func (h *Handler) netChallengeReason(ip string, cfg settings.Settings) string {
	if h.IPGeo == nil || ip == "" {
		return ""
	}
	info := h.IPGeo.LookupInfo(ip)
	if h.IPGeo.ASNLoaded() {
		if d, _, rate, ok := asnResolve(info.ASN, info.ASNOrg, cfg.Nginx.Asn); ok && d.sev != sevPass && rate == 0 {
			return "asn"
		}
	}
	if h.IPGeo.Loaded() {
		cc := strings.ToUpper(strings.TrimSpace(info.Country))
		if d, rate, ok := geoDecideForCountry(cc, cfg.Nginx.Geo); ok && d.sev != sevPass && rate == 0 {
			return "geo"
		}
	}
	return ""
}

// ja4Decide returns a challenge decision when the JA4 verdict says "bot".
// Severity is captcha_only (= JA4 bot is a strong signal so the chain
// skips PoW and goes straight to CAPTCHA, matching the legacy semantics).
// communityBansMatcher returns the enforceable shared feed, or nil when this
// install has no client wired (= tests, or submit/subscribe never configured).
// A nil *Matcher never hits, so callers need no guard of their own.
func (h *Handler) communityBansMatcher() *communitybans.Matcher {
	if h == nil || h.CommunityBans == nil {
		return nil
	}
	return h.CommunityBans.Matcher()
}

// communityBansDecide: the unmask.sh shared feed as a first-class axis.
//
// Native mode enforces the feed through nginx map lookups against
// community-bans-{ipja4,ja4,ip}.map.  A forward-auth node -- Apache, or nginx
// without the module -- has no such maps, so before this axis existed those
// deployments pulled the feed, listed it in the UI, and enforced none of it:
// the subscription was decorative on exactly the deploy mode that cannot see
// the maps.  The daemon now loads those same files into memory
// (communitybans.Matcher), so both wires answer from the same bytes.
//
// The rescues a feed entry must never override (search bot, bypass IP, bypass
// path, valid _bv) sit in the veto switch above this axis, matching the native
// map's ordering.
func communityBansDecide(m *communitybans.Matcher, ip, ja4 string, cfg settings.Settings) (axisDecision, bool) {
	if !cfg.CommunityBans.ApplyActive() {
		return axisDecision{}, false
	}
	kind, ok := m.Hit(ip, ja4)
	if !ok {
		return axisDecision{}, false
	}
	act := cfg.CommunityBans.ResolvedAction()
	reason := "community_bans:" + kind
	if act == settings.RateChallengeDeny {
		return axisDecision{sev: sevDeny, reason: reason}, true
	}
	s := severityFromAction(act)
	return axisDecision{sev: s, reason: reason, chMode: chModeFromSeverity(s)}, true
}

func ja4Decide(ja4Action, ja4Verdict string, n settings.Nginx) (axisDecision, bool) {
	if ja4Action != "bot" {
		return axisDecision{}, false
	}
	// The operator's configured chain (tab default -> preset -> row), the same
	// resolver the native serve path uses.  This axis used to hardcode
	// captcha_only and never read settings at all, so every JA4 action picked in
	// the UI applied on native and did nothing behind a load balancer.
	act := nginxconf.ResolveJA4VerdictAction(ja4Verdict, n)
	if act == "" {
		act = settings.RateChallengeCaptchaOnly // historical default for this axis
	}
	if act == settings.RateChallengeDeny {
		// deny is terminal: no chain to serve.  The rescues (search bot, bypass
		// IP / path) sit above this in the decision switch, so a JA4 deny cannot
		// take out a crawler the operator meant to let through.
		return axisDecision{sev: sevDeny, reason: "ja4:" + ja4Verdict + ":deny"}, true
	}
	s := severityFromAction(act)
	return axisDecision{
		sev:    s,
		reason: "ja4:" + ja4Verdict,
		chMode: chModeFromSeverity(s),
	}, true
}

// uaDecide runs the UA classification chain.  search_ai UAs contribute a
// pass (= sevPass) so other axes can still escalate; explicit challenge-
// target hits contribute a captcha challenge; otherwise the Global axis
// (Known/Unknown action) sets severity.
//
// rangeVerifiedUA (nil = feature inert) suppresses the search_ai pass for
// crawler UAs whose rescue rides their vendor's IP-range presets: by the
// time uaDecide runs, the bypass-IP veto has already passed the genuine
// article, so a surviving match here is a spoof and takes the Global axis
// like any unknown client.
func uaDecide(ua, ja4Action string, cfg settings.Settings, rangeVerifiedUA *regexp.Regexp) (axisDecision, bool) {
	switch classify.IsBot(ua, ja4Action).String() {
	case "search_ai":
		if rangeVerifiedUA == nil || !rangeVerifiedUA.MatchString(ua) {
			return axisDecision{sev: sevPass, reason: "ua:search_ai"}, true
		}
	}
	if listed, category, rowAct := lookupUAListed(ua, cfg.Nginx); listed != "" && category == "challenge" {
		// The black-list chain, through the one resolver the native serve
		// path, the CAPTCHA-grade calculation and the admin UI all read.
		// This used to fall back to a hardcoded captcha_only when the picker
		// was unset -- predating the picker -- so an unset install challenged
		// the same UA harder here than on the module, and harder than every
		// screen in the admin said it would.
		act := cfg.UABlacklistChain()
		// A row that pinned its own chain wins over the list default, the
		// same way a preset's PresetAction override does on the native side.
		if settings.IsValidRateChallengeMode(rowAct) {
			act = rowAct
		}
		s := severityFromAction(act)
		return axisDecision{
			sev:    s,
			reason: "ua:target:" + listed,
			chMode: chModeFromSeverity(s),
		}, true
	}
	var pick string
	if classify.IsKnownBrowser(ua) {
		pick = cfg.Global.KnownBrowserAction
	} else {
		pick = cfg.Global.UnknownUAAction
	}
	if pick == "" {
		pick = settings.RateChallengePoWOnly
	}
	// Stale-browser escalation (mirrors ServeChallenge on the native path): a UA
	// far behind current Chrome stable is a headless-scraper tell; serve it the
	// operator's stale action (default captcha_only) even when the Global pick
	// would pass or only PoW.  The stale action REPLACES the pick — it is the
	// operator's explicit choice for these UAs, so captcha_only wins even over a
	// pow_then_captcha pick (skip the pointless PoW).  A deny pick is left intact
	// (never soften a hard block).  uaDecide runs after Phase A's veto-passes, so
	// a bypass-IP monitoring probe / search bot / valid _bv never reaches here.
	staleReason := ""
	if g := cfg.Global; g.StaleBrowserEnabled() && pick != settings.RateChallengeDeny &&
		classify.IsStaleBrowser(ua, g.CurrentChromeMajorResolved(), g.CurrentFirefoxMajorResolved(),
			g.FirefoxESRMajors(), g.StaleBrowserLagN(), g.FirefoxStaleLagN()) {
		pick = g.StaleBrowserResolvedAction()
		staleReason = "ua:stale_browser:" + pick
	}
	if pick == "pass" {
		label := "ua:unknown"
		if classify.IsKnownBrowser(ua) {
			label = "human"
		}
		return axisDecision{sev: sevPass, reason: label}, true
	}
	tag := "ua:unknown"
	if classify.IsKnownBrowser(ua) {
		tag = "ua:browser"
	}
	s := severityFromAction(pick)
	reason := tag + ":" + pick
	if staleReason != "" {
		reason = staleReason
	}
	return axisDecision{sev: s, reason: reason, chMode: chModeFromSeverity(s)}, true
}

// isSearchBotUA reports whether the UA is a rescued search / AI crawler that
// must pass regardless of the gating axes (= the project's #1 rule: never block
// Googlebot / GPTBot / ClaudeBot / Bingbot / ...).  Native mode's is_search_bot
// map exempts such a request ABOVE geo / protected / ja4 / honeypot; forward-auth
// must do the same as a veto-pass, not the weak sevPass vote in uaDecide that
// loses the max-severity to any deny/challenge axis (= the ranking-accident
// bug).  Covers both the crawler-user-agents.json match (classify.IsBot ->
// search_ai) AND a preset/operator UA-list entry categorized search_ai (which
// uaDecide's max-severity branch only checked for "challenge", ignoring these).
func isSearchBotUA(ua, ja4Action string, n settings.Nginx, rangeVerifiedUA *regexp.Regexp) bool {
	if classify.IsBot(ua, ja4Action).String() == "search_ai" {
		// Range-verified crawler UAs are exempt from the UA-string rescue:
		// the vendor's enabled IP-range presets carry it (the genuine crawler
		// already passed via the bypass-IP veto, which runs right after this
		// check).  An operator Extra row can still rescue the UA below.
		if rangeVerifiedUA == nil || !rangeVerifiedUA.MatchString(ua) {
			return true
		}
	}
	if listed, category, _ := lookupUAListed(ua, n); listed != "" && category == "search_ai" {
		return true
	}
	return false
}

// --- helpers ---

// headerOrFallback returns the named header when the proxy SET it -- including
// when it set it empty -- and otherwise the first non-empty fallback.
//
// Header.Get cannot tell "absent" from "present but empty", and the difference
// matters for the X-Original-* protocol: a proxy speaking it has already told
// us what the visitor sent, so an empty value is an answer, not a gap.  Only a
// caller that never set the header at all should fall through.
func headerOrFallback(r *http.Request, name string, fallbacks ...string) string {
	if _, ok := r.Header[textproto.CanonicalMIMEHeaderKey(name)]; ok {
		return strings.TrimSpace(r.Header.Get(name))
	}
	return firstNonEmpty(fallbacks...)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// normalizeSite turns a request Host into a stable site identifier:
// lowercased, :port stripped, capped at 64 bytes (= the unmask_event.site
// column width).  An empty / unusable host falls back to defaultSite.
func normalizeSite(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return defaultSite
	}
	// Strip a :port suffix — handles "host:8080" and "[::1]:8080".
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	// Drop a trailing FQDN dot.  Browsers and curl will happily send
	// `Host: example.com.` (= absolute DNS form), but the operator typed
	// `example.com` into the per-site config -- without this strip the two
	// would key different rows and the request would fall back to defaultSite
	// (= an operator running monitor-mode on the default while challenging
	// per-site would be silently bypassable via that one extra dot).
	host = strings.TrimRight(host, ".")
	// Keep only hostname-safe characters (a-z 0-9 . - _ and : for IPv6
	// literals).  Bounds the value so it is safe to interpolate into the site
	// SQL fragment and stops a junk Host from polluting the site column.
	host = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == ':':
			return r
		default:
			return -1
		}
	}, host)
	if len(host) > 64 {
		host = host[:64]
	}
	if host == "" {
		return defaultSite
	}
	return host
}

// schemeFromRequest derives the request scheme ("http" / "https") server-
// side.  Trusts X-Forwarded-Proto because the nginx-rendered admin upstream
// sets it via `proxy_set_header X-Forwarded-Proto $scheme;` unconditionally
// (= the value reflects what nginx itself terminated on and the client cannot
// influence it).  Falls back to r.TLS for direct-to-admin requests (= dev
// mode without nginx in front).  Returns "" only when neither is available.
func schemeFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); v != "" {
		v = strings.ToLower(v)
		if v == "https" || v == "http" {
			return v
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return ""
}

// portFromRequest returns the listener port from X-Forwarded-Port (= set
// server-side by the nginx-rendered admin upstream so the client cannot
// influence it).  Falls back to the Host header's :port for direct-to-admin
// requests.  0 = unknown.
// localPortNote returns the port THIS nginx accepted on (X-Unmask-Local-Port)
// when it disagrees with the client-facing port recorded for the event, else 0.
//
// They disagree exactly when a load balancer forwarded the request: it sends
// X-Forwarded-Proto but commonly no X-Forwarded-Port (GCP's does not), so the
// client-facing port is inferred from the scheme.  Carrying the accepted port
// only in that case keeps the payload unchanged for everyone not behind an LB,
// and lets the hunt popover show the inference beside the fact it was inferred
// from -- an LB terminating on a non-standard port is visible instead of
// silently recorded as 443.
func localPortNote(r *http.Request, reportedPort int) int {
	v := strings.TrimSpace(r.Header.Get("X-Unmask-Local-Port"))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > 65535 || n == reportedPort {
		return 0
	}
	return n
}

func portFromRequest(r *http.Request) int {
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
			return n
		}
	}
	if _, p, err := net.SplitHostPort(r.Host); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
			return n
		}
	}
	return 0
}

// siteFromRequest derives the site identifier for an event.  The site is the
// visitor's request Host (= the vhost they reached), so a host serving many
// vhosts splits cleanly in the dashboard with no per-site config.  The
// X-Unmask-Site header is an explicit override for proxies that map vhosts to
// a custom site id.
func siteFromRequest(r *http.Request, cfg settings.Settings) string {
	// X-Unmask-Site lets an operator override the host-derived site.  But the
	// peer being trusted (= loopback in forward-auth) does NOT make the header
	// VALUE trustworthy: nginx's default proxy_pass_request_headers forwards a
	// client-supplied X-Unmask-Site, and the admin can't distinguish that from
	// an operator-set one.  So honor it ONLY when the operator has explicitly
	// opted in (and thereby promised the proxy OVERWRITES the header), else a
	// client spoofs it to select a weaker site's policy (observe_only =
	// install-wide bypass).  Default: derive the site from the proxy-forced
	// X-Original-Host below, which a client can't set.
	if cfg.Nginx.TrustForwardedSite && peerIsTrustedProxy(r.RemoteAddr, forwardAuthTrustedPeers(cfg)) {
		if s := strings.TrimSpace(r.Header.Get("X-Unmask-Site")); s != "" {
			return normalizeSite(s)
		}
	}
	return normalizeSite(firstNonEmpty(
		r.Header.Get("X-Original-Host"),
		r.Header.Get("X-Forwarded-Host"),
		r.Host,
	))
}

// forwardAuthTrustedPeers builds the CIDR list that gates whether
// X-Client-JA4 is honored: the loopback range (= nginx ↔ admin via local
// upstream, the default deployment shape) plus every CIDR configured for
// native-mode LB trust (= settings.Nginx.TrustedLBPresets / TrustedLBExtra).
// Operators configure one list; both modes consume it.
func forwardAuthTrustedPeers(cfg settings.Settings) []string {
	peers := []string{"127.0.0.0/8", "::1/128"}
	peers = append(peers, nginxconf.EffectiveLBCIDRs(cfg.Nginx)...)
	return peers
}

// resolveForwardedJA4 extracts the client JA4 from the X-Client-JA4
// (fallback X-Original-JA4) request header, gated on the connection peer
// being inside forwardAuthTrustedPeers().  Any other case returns ""
// (= no JA4; the ja4 axis stays silent).
//
// Why peer-based: the upstream proxy (nginx native plugin / nginx
// auth_request / Apache mod_lua / an LB / CDN) is what
// opens the TCP connection to /api/check, so r.RemoteAddr is that proxy's
// address.  The visitor sits behind it and must never be used for this
// trust decision.  Spoof defense is two-layer: this peer check, plus the
// proxy snippet overwriting any client-supplied X-Client-JA4 before it
// forwards the request.
func resolveForwardedJA4(r *http.Request, cfg settings.Settings) string {
	ja4 := firstNonEmpty(
		r.Header.Get("X-Client-JA4"),
		r.Header.Get("X-Original-JA4"),
	)
	if ja4 == "" {
		return ""
	}
	// First gate: the header must reach us THROUGH a trusted proxy.  In nginx
	// forward-auth the value is also edge-gated (forward-auth-lbtrust.conf sets
	// X-Client-JA4 to the real client JA4 only for a trusted-LB source, else ""),
	// so a direct visitor's spoof is already "" by here; this peer check stops a
	// client that reaches the admin port directly.  The peer is the proxy
	// (loopback for the local nginx/apache, or a trusted-LB CIDR when an LB
	// talks to the admin directly).
	if !peerIsTrustedProxy(r.RemoteAddr, forwardAuthTrustedPeers(cfg)) {
		return ""
	}
	// Second gate (Apache forward-auth): Apache can't gate the value in the web
	// server (no geo / map), so apache-unmask.lua reports the real connecting
	// peer in X-Unmask-Conn-Peer (= mod_rewrite %{CONN_REMOTE_ADDR}, which
	// mod_remoteip does NOT rewrite).  Honor the JA4 only when that peer is a
	// configured trusted LB -- so a client reaching Apache directly (conn-peer =
	// the client itself) has its forged JA4 dropped here.  nginx edge-gates
	// instead and strips this header, so the check is a no-op there.  An empty
	// trusted-LB list makes IsTrustedLBIP false, so a stray conn-peer can never
	// smuggle a JA4 in.
	if connPeer := strings.TrimSpace(r.Header.Get("X-Unmask-Conn-Peer")); connPeer != "" {
		if trusted, _ := nginxconf.IsTrustedLBIP(connPeer, cfg.Nginx); !trusted {
			return ""
		}
	}
	// Shape-validate before the value reaches matchJA4 / the event record.
	return safeJA4(ja4)
}

// peerIsTrustedProxy reports whether the raw connection address (host:port
// from r.RemoteAddr) falls inside one of the trusted-proxy CIDRs.
func peerIsTrustedProxy(remoteAddr string, cidrs []string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	peer := net.ParseIP(strings.Trim(host, "[]"))
	if peer == nil {
		return false
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if ipnet.Contains(peer) {
			return true
		}
	}
	return false
}

// detectLBHeaderWarning flags an LB-forwarded header that the admin's trust
// config rejects, so the value was silently dropped.  Cases:
//   - X-Client-JA4 from a peer outside forwardAuthTrustedPeers (loopback +
//     trusted-LB CIDRs) = a misconfigured proxy chain or a direct visitor
//     trying to spoof the header.  (The value-trust itself is gated in nginx by
//     forward-auth-lbtrust.conf, so there is no admin-side JA4 toggle.)
//   - X-Unmask-Site sent but TrustForwardedSite is OFF, or from an untrusted
//     peer (= operator wired the proxy to forward the site but never opted in,
//     or a spoof attempt).
//
// Returns the reason string (suitable for payload.lb_warning) or "" when no
// warning applies.  Cheap: a couple of header reads + a CIDR scan.
func detectLBHeaderWarning(r *http.Request, cfg settings.Settings) string {
	hasJA4 := r.Header.Get("X-Client-JA4") != "" || r.Header.Get("X-Original-JA4") != ""
	hasSite := r.Header.Get("X-Unmask-Site") != ""
	if !hasJA4 && !hasSite {
		return ""
	}
	var peerOK bool
	if hasJA4 || hasSite {
		peerOK = peerIsTrustedProxy(r.RemoteAddr, forwardAuthTrustedPeers(cfg))
	}
	var reasons []string
	if hasJA4 && !peerOK {
		reasons = append(reasons, "X-Client-JA4 from untrusted peer")
	}
	if hasSite {
		if !cfg.Nginx.TrustForwardedSite {
			reasons = append(reasons, "X-Unmask-Site sent but trust_forwarded_site is OFF")
		} else if !peerOK {
			reasons = append(reasons, "X-Unmask-Site from untrusted peer")
		}
	}
	return strings.Join(reasons, "; ")
}

// --- Regex matcher cache (= recompile only when settings change) ---

type pathMatchers struct {
	bypass    []*regexp.Regexp
	geoExempt []*regexp.Regexp // country-axis-only exemption (RSS/Atom feeds etc.); asn/ja4/honeypot/ua still run
	asnExempt []*regexp.Regexp // ASN-axis-only exemption; geo/ja4/honeypot/ua still run
	honeypot  []honeypotRule
	protected []*regexp.Regexp
	ipBypass  *nginxconf.IPBypassMatcher
	// rangeVerifiedUA: alternation over the crawler UA patterns whose rescue
	// rides the enabled IP-range presets instead of the UA string (see
	// nginxconf/uarange.go).  A UA matching this is NOT rescued as search_ai;
	// the genuine crawler passes via ipBypass (its vendor ranges are folded
	// into that matcher), a spoof falls through to the gating axes.  nil when
	// no pattern is inverted.
	rangeVerifiedUA *regexp.Regexp
	// notifPreviewUA: alternation over the notification-preview group's
	// enabled patterns (classify.NotificationPreviewTag).  Rescue is guarded:
	// a match passes only together with Apple's TLS fingerprint -- see
	// notifPreviewRescue.  nil when the group is not white or every pattern
	// is disabled.
	notifPreviewUA *regexp.Regexp
}

// notifPreviewRescue mirrors native's guarded notification-preview composite:
// UA matches the group AND the JA4 carries Apple's cipher-suite hash.  ja4 ==
// "" (plain HTTP, or a TLS-terminating hop that hides the client hello) never
// rescues -- the visitor just takes the normal challenge flow.
func notifPreviewRescue(ua, ja4 string, m pathMatchers) bool {
	return m.notifPreviewUA != nil && ja4 != "" &&
		strings.Contains(ja4, classify.AppleCFNetworkJA4B) &&
		m.notifPreviewUA.MatchString(ua)
}

// honeypotRule pairs a compiled honeypot pattern with its per-preset
// (PresetAction[groupID]) / per-URL (HoneypotURL.Action) action override; ""
// means "inherit Honeypot.DefaultAction".  Carrying the action on the matcher
// lets honeypotDecide both return the per-preset immediate decision AND persist
// the override on the ban (so subsequent requests honor it) without re-resolving
// which rule matched.
type honeypotRule struct {
	re     *regexp.Regexp
	action string
}

// bypassMatchersCache: reused until the (published-snapshot pointer, site)
// pair changes.  The key is the pointer the handler PUBLISHES (settingsPtr
// via h.cfg()) — settings updates swap that pointer, so it identifies a
// settings generation.  site is part of the key so swapping vhosts
// mid-process does not return a cached compile that was filtered for a
// different host.  (The original key was the address of a per-call value
// copy, which never matched — every /api/check rebuilt ~100 matchers.)
var (
	matchersMu     sync.Mutex
	cachedSnap     *settings.Settings
	cachedSite     string
	cachedMatchers pathMatchers
)

// reCache memoizes compiled patterns by their STRING, which always compiles to
// the same regex -- so it is staleness-free (unlike the settings-pointer cache
// above, whose key `&n` is a fresh local-copy address that never matches, so it
// recompiled ~100 preset regexes on EVERY /api/check under matchersMu = an
// unauthenticated CPU sink).  Bounded by the count of distinct preset+operator
// patterns (finite, not request-controllable), so it can't grow unboundedly.
var reCache sync.Map // pattern string -> *regexp.Regexp (nil = compile failed)

func compileCachedRe(pattern string) *regexp.Regexp {
	if v, ok := reCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re // may be nil = a previously-cached compile failure
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		reCache.Store(pattern, (*regexp.Regexp)(nil))
		return nil
	}
	reCache.Store(pattern, re)
	return re
}

// bypassMatchers: build the per-site regex list from settings.  Uses
// BypassPathsConfig.ResolvePaths(site) / ProtectedPathsConfig.ResolvePaths /
// HoneypotConfig.ResolveURLs so a row's Site filter is honored once, here,
// and the downstream matchers stay site-agnostic.
//
// snap must be the PUBLISHED snapshot pointer (h.cfg()), not the address of
// a local copy — the cache above keys on it.
func (h *Handler) bypassMatchers(snap *settings.Settings, site string) pathMatchers {
	matchersMu.Lock()
	defer matchersMu.Unlock()
	if cachedSnap == snap && cachedSite == site {
		return cachedMatchers
	}
	n := snap.Nginx
	pm := pathMatchers{}

	// bypass IPs (CHALLENGE side): preset ranges (Googlebot etc.) + enabled
	// bypass_ips rows + stats_exclude, CIDR-aware -- exactly the set the native
	// geo $is_bypass_ip block bakes in, so forward-auth never challenges a trusted
	// crawler / monitoring probe the native path would exempt.  This is the
	// challenge matcher, NOT the ban guard (banDecide above uses BanMgr, whose
	// whitelist is the narrower NewIPBypassMatcher set without stats_exclude).
	pm.ipBypass = nginxconf.NewChallengeBypassMatcher(n)

	// Range-backed crawler UA patterns whose UA-string rescue is off
	// (uarange.go): one alternation regex.  compileCachedRe memoizes by the
	// joined string, so the hot path pays a map lookup, not a compile.
	if pats := nginxconf.SortedUpstreamUAOff(n); len(pats) > 0 {
		pm.rangeVerifiedUA = compileCachedRe("(?i)(?:" + strings.Join(pats, ")|(?:") + ")")
	}

	// Guarded notification-preview UA matcher (rescue = UA + Apple TLS, see
	// notifPreviewRescue).  Built from the group's enabled patterns so the
	// per-pattern disable and the group-mode override behave exactly like the
	// native render (collectUpstreamPatternsByMode).
	if classify.ResolveGroupMode(classify.NotificationPreviewTag, n.SearchBots.UpstreamGroupMode) == classify.GroupModeWhite {
		disabled := map[string]bool{}
		for _, p := range n.SearchBots.UpstreamDisabled {
			disabled[p] = true
		}
		var pats []string
		for _, e := range classify.UpstreamRescueList()[classify.NotificationPreviewTag] {
			if e.Pattern != "" && !disabled[e.Pattern] {
				pats = append(pats, e.Pattern)
			}
		}
		if len(pats) > 0 {
			pm.notifPreviewUA = compileCachedRe("(?i)(?:" + strings.Join(pats, ")|(?:") + ")")
		}
	}

	// bypass paths: enabled presets + per-site rows from ResolvePaths.
	//
	// Pattern convention: BypassPathRule.Pattern is a **path-anchored** PCRE
	// regex evaluated against the URI directly (e.g., `^/api/`).  We compile
	// it as-is with a case-insensitive flag; no anchor manipulation, matching
	// what the nginx renderer feeds into `map $request_uri ...`.
	//
	// Preset resolution: per-preset DefaultOn + operator deviations via the
	// shared EffectiveBypassPathPresets — so admin's in-memory check agrees with
	// the nginx config it produced.
	enabledBP := nginxconf.EffectiveBypassPathPresets(n.BypassPaths.EnabledPresets, n.BypassPaths.DisabledPresets)
	for _, g := range nginxconf.BypassPathPresetGroups {
		if !enabledBP[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			if r.Site != "" && r.Site != site {
				continue
			}
			// Case-SENSITIVE, matching the native render's "~" map (the
			// block lists below use "~*" on both wires -- see the pass-list
			// note on compileExemptRows).
			if re := compileCachedRe(r.Pattern); re != nil {
				pm.bypass = append(pm.bypass, re)
			}
		}
	}
	for _, row := range n.BypassPaths.ResolvePaths(site) {
		if row.Disabled {
			continue
		}
		if re := compileCachedRe(row.Path); re != nil {
			pm.bypass = append(pm.bypass, re)
		}
	}

	// Per-axis exempt paths (no presets).  Same compile convention as bypass
	// paths; each list is matched in the decision's default case to skip ONLY
	// its own axis (geoDecide or asnDecide).
	// Pass lists (bypass / geo-exempt / asn-exempt) compile case-SENSITIVE,
	// the same as the native render's "~" maps -- forward-auth used to fold in
	// "(?i)" and quietly passed /STATIC/ where native challenged it, and for a
	// list whose entries SKIP enforcement the narrower reading is the safe
	// one.  Block lists (protected paths / honeypot) stay case-insensitive on
	// both wires, where wider is the safe direction.  An operator who wants
	// either one relaxed writes "(?i)" into the pattern: both PCRE (nginx) and
	// RE2 (Go) honour it.
	compileExemptRows := func(rows []settings.BypassPath) (out []*regexp.Regexp) {
		for _, row := range rows {
			if row.Disabled {
				continue
			}
			if re := compileCachedRe(row.Path); re != nil {
				out = append(out, re)
			}
		}
		return out
	}
	pm.geoExempt = compileExemptRows(n.Geo.ResolveExemptPaths(site))
	pm.asnExempt = compileExemptRows(n.Asn.ResolveExemptPaths(site))

	// honeypot: enabled presets + per-site URLs.  Each rule carries its
	// per-preset (PresetAction[g.ID]) / per-row (u.Action) action override so
	// honeypotDecide can apply + persist it ("" = inherit DefaultAction).  The
	// active-set logic (OptIn / Disabled / Enabled) mirrors render.go +
	// nginxconf.ResolveHoneypotAction so all three modes agree on which presets
	// are live -- previously this scan honored only DisabledPresets, silently
	// activating OptIn presets (e.g. sql-injection) the operator never enabled.
	disabledHP := toSet(n.Honeypot.DisabledPresets)
	enabledHP := toSet(n.Honeypot.EnabledPresets)
	for _, g := range nginxconf.HoneypotPresetGroups {
		if g.OptIn {
			if !enabledHP[g.ID] {
				continue
			}
		} else if disabledHP[g.ID] {
			continue
		}
		if !g.OptIn && nginxconf.EnforcementHeld(n, g.AddedIn) {
			continue // held pending upgrade review -- match native render
		}
		act := strings.TrimSpace(n.Honeypot.PresetAction[g.ID])
		for _, p := range g.Patterns {
			if re := compileCachedRe("(?i)" + p); re != nil {
				pm.honeypot = append(pm.honeypot, honeypotRule{re: re, action: act})
			}
		}
	}
	for _, u := range n.Honeypot.ResolveURLs(site) {
		if u.Disabled {
			continue
		}
		if re := compileCachedRe("(?i)" + u.Path); re != nil {
			pm.honeypot = append(pm.honeypot, honeypotRule{re: re, action: strings.TrimSpace(u.Action)})
		}
	}

	// protected paths: presets + per-site rows.
	enabledPP := toSet(n.ProtectedPaths.EnabledPresets)
	for _, g := range nginxconf.ProtectedPathPresetGroups {
		if !enabledPP[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			if re := compileCachedRe("(?i)" + r.Pattern); re != nil {
				pm.protected = append(pm.protected, re)
			}
		}
	}
	for _, row := range n.ProtectedPaths.ResolvePaths(site) {
		if row.Disabled {
			continue
		}
		if re := compileCachedRe("(?i)" + row.Path); re != nil {
			pm.protected = append(pm.protected, re)
		}
	}

	cachedSnap = snap
	cachedSite = site
	cachedMatchers = pm
	return pm
}

// matchPath reports whether the URI hits any of the compiled bypass regex.
// site filtering happened once in bypassMatchers, so this is a flat scan.
func matchPath(uri string, list []*regexp.Regexp) bool {
	for _, re := range list {
		if re.MatchString(uri) {
			return true
		}
	}
	return false
}

// matchJA4: JA4 hash -> (verdict, action).  Enabled presets ->
// enabled extras in order, first match wins.  No match -> "" / "ok".
//
// Reproduce the same logic as the nginx JA4 verdict map on the Go
// side.  Used when X-Client-JA4 arrives via a GCP LB rather than via
// the nginx module.
func matchJA4(ja4 string, n settings.Nginx) (verdict, action string) {
	v, a, _ := lookupJA4Verdict(ja4, n)
	return v, a
}

// resolvedVerdictName derives the JA4 verdict NAME from the client JA4 the
// request carries (X-Client-JA4 = nginx's $effective_ja4).  The verdict name is
// a display-only label that unmask owns -- nginx only needs the bot/not action
// decision -- so every recorded event takes the name the daemon resolves here
// rather than trusting the X-JA4-Verdict header.  "" when no rule matched (the
// events table renders that as "ok").  matchJA4 reproduces the nginx
// $ja4_verdict map exactly, so native and forward-auth store identical names.
func (h *Handler) resolvedVerdictName(ja4 string) string {
	v, _ := matchJA4(ja4, h.cfg().Nginx)
	return v
}

// lookupJA4Verdict: extended matchJA4 that also returns the hit
// source (= "preset:<id>" or "extra").  The bot-hunt tab's "already
// registered" display needs the source info.
func lookupJA4Verdict(ja4 string, n settings.Nginx) (verdict, action, source string) {
	if ja4 == "" {
		return "", "ok", ""
	}
	disabled := map[string]bool{}
	for _, id := range n.JA4Verdicts.DisabledPresets {
		disabled[strings.TrimSpace(id)] = true
	}
	for _, g := range nginxconf.JA4VerdictGroups {
		if disabled[g.ID] || nginxconf.EnforcementHeld(n, g.AddedIn) {
			continue
		}
		for _, rule := range g.Rules {
			if matchedRegex(rule.Pattern, ja4) {
				return rule.Verdict, rule.Action, "preset:" + g.ID
			}
		}
	}
	for i, p := range n.JA4Verdicts.Extra {
		if i < len(n.JA4Verdicts.ExtraDisabled) && n.JA4Verdicts.ExtraDisabled[i] {
			continue
		}
		if matchedRegex(p.Pattern, ja4) {
			return p.Verdict, p.Action, "extra"
		}
	}
	return "", "ok", ""
}

// lookupUAListed: if the UA hits any of search_bots /
// challenge_targets presets / extras, return the listed name, category, and
// the chain that entry pinned for itself (empty = inherit the list default).
// Unregistered -> "" / "" / "".
//
// category:
//
//	"search_ai"  : matched SearchBots (= normally rescued)
//	"challenge"  : matched ChallengeTargets (= normally blocked)
//	""           : matched neither (= normal human handling -> show the button)
func lookupUAListed(ua string, n settings.Nginx) (listed, category, action string) {
	if ua == "" {
		return "", "", ""
	}
	// SearchBots rescue list.  The built-in Googlebot / GPTBot / ... presets
	// were removed (the crawler-user-agents.json upstream path in
	// classify.IsBot already covers them, and isSearchBotUA checks that
	// first); only the operator's own extra patterns remain here.
	for i, p := range n.SearchBots.Extra {
		if i < len(n.SearchBots.ExtraDisabled) && n.SearchBots.ExtraDisabled[i] {
			continue
		}
		if matchedRegex(p, ua) {
			return "extra", "search_ai", ""
		}
	}
	// ChallengeTargets: the block list (= curl / Python-Requests / Headless etc.)
	disabledCT := map[string]bool{}
	for _, id := range n.ChallengeTargets.DisabledPresets {
		disabledCT[strings.TrimSpace(id)] = true
	}
	for _, g := range nginxconf.ChallengeTargetGroups {
		if disabledCT[g.ID] || nginxconf.EnforcementHeld(n, g.AddedIn) {
			continue
		}
		for _, p := range g.Patterns {
			if matchedRegex(p, ua) {
				// The preset's own chain, when the operator pinned one.  Dropping
				// it here (as this used to) left forward-auth resolving only
				// DefaultAction while the native render honoured
				// ChallengeTargets.PresetAction -- so a preset pinned to a
				// captcha chain was enforced on one wire and not the other, and
				// the CAPTCHA-grade gate (which reads this action) let a
				// proof-of-work cookie through in forward-auth.
				return g.ID, "challenge", strings.TrimSpace(n.ChallengeTargets.PresetAction[g.ID])
			}
		}
	}
	for i, p := range n.ChallengeTargets.Extra {
		if i < len(n.ChallengeTargets.ExtraDisabled) && n.ChallengeTargets.ExtraDisabled[i] {
			continue
		}
		if matchedRegex(p, ua) {
			// The row's own chain, when it pinned one.  Both callers apply it
			// over ChallengeTargets.DefaultAction, the same way a preset's
			// PresetAction override does.
			act := ""
			if i < len(n.ChallengeTargets.ExtraAction) {
				act = strings.TrimSpace(n.ChallengeTargets.ExtraAction[i])
			}
			return "extra", "challenge", act
		}
	}
	// Upstream rescue groups (= crawler-user-agents.json categories) resolved
	// to mode=black contribute additional challenge-target UAs.  The nginx
	// render side already pushes these into the $is_challenge_target map; this
	// branch keeps the admin's auth_request decision symmetric (otherwise
	// curl / python-requests / Headless variants would 401 in native mode but
	// 200 in forward-auth mode).
	upstreamDisabled := map[string]bool{}
	for _, p := range n.SearchBots.UpstreamDisabled {
		upstreamDisabled[strings.TrimSpace(p)] = true
	}
	for cat, entries := range classify.UpstreamRescueList() {
		if classify.ResolveGroupMode(cat, n.SearchBots.UpstreamGroupMode) != classify.GroupModeBlack {
			continue
		}
		for _, e := range entries {
			if upstreamDisabled[e.Pattern] {
				continue
			}
			if matchedRegex(e.Pattern, ua) {
				// Same for a rescue group the operator flipped to black and
				// pinned a chain on: the native render applies
				// SearchBots.UpstreamGroupAction, so forward-auth must too.
				return cat, "challenge", strings.TrimSpace(n.SearchBots.UpstreamGroupAction[cat])
			}
		}
	}
	return "", "", ""
}

// anyUADenyConfigured: does ANY UA-list source name "deny"?  String compares
// only -- no regex, no UA involved -- so hardDenyUA can bail before the scan.
func anyUADenyConfigured(n settings.Nginx) bool {
	ct := n.ChallengeTargets
	if strings.TrimSpace(ct.DefaultAction) == settings.RateChallengeDeny {
		return true
	}
	for _, a := range ct.ExtraAction {
		if strings.TrimSpace(a) == settings.RateChallengeDeny {
			return true
		}
	}
	for _, a := range ct.PresetAction {
		if strings.TrimSpace(a) == settings.RateChallengeDeny {
			return true
		}
	}
	for _, a := range n.SearchBots.UpstreamGroupAction {
		if strings.TrimSpace(a) == settings.RateChallengeDeny {
			return true
		}
	}
	return false
}

// hardDenyUA reports whether the UA black list resolves ua to "deny".
//
// ANY matching source saying deny is decisive -- the list default, the
// operator's own row, an upstream group, a preset.  That is not the
// last-writer-wins rule the ordinary chain uses further down ServeChallenge,
// and deliberately so: that rule picks among challenge chains, where "which
// screen" is a preference, while this one answers "is this client served at
// all", where the strongest statement has to win.  It is the same
// max-severity rule the security axes already compose by, and it is what lets
// the nginx render (hardDenyUAPatterns) emit a flat pattern list that cannot
// disagree with this function.
func hardDenyUA(ua string, n settings.Nginx) bool {
	// No early-out on an empty UA, unlike lookupUAListed.  nginx matches
	// $http_user_agent against the pattern list whatever it holds, and one of
	// the shipped presets is "^.{0,5}$" -- an absent UA matches it.  Skipping
	// the empty case here would have denied a headerless client in native mode
	// and passed the same client in forward-auth, which is the divergence
	// TestHardDenyRenderMatchesTheDaemon exists to catch (it caught this).
	ct := n.ChallengeTargets
	// Cheap precheck first.  This is called from the decision switch, so it runs
	// for nearly every forward-auth request, and the scan below walks every
	// preset pattern -- the same work the UA axis already does further down.  An
	// install that denies nothing by UA (most of them, and every fleet node
	// today) can answer from a handful of string compares instead.  Mirrors the
	// render side, which emits no deny plumbing at all in that case.
	if !anyUADenyConfigured(n) {
		return false
	}
	def := strings.TrimSpace(ct.DefaultAction)
	denies := func(act string) bool {
		if act = strings.TrimSpace(act); act == "" {
			act = def
		}
		return act == settings.RateChallengeDeny
	}
	disabled := map[string]bool{}
	for _, id := range ct.DisabledPresets {
		disabled[strings.TrimSpace(id)] = true
	}
	for _, g := range nginxconf.ChallengeTargetGroups {
		if disabled[g.ID] || nginxconf.EnforcementHeld(n, g.AddedIn) || !denies(ct.PresetAction[g.ID]) {
			continue // held pending upgrade review -- match native uaPatternsWhereAction
		}
		for _, p := range g.Patterns {
			if matchedRegex(p, ua) {
				return true
			}
		}
	}
	for i, p := range ct.Extra {
		if i < len(ct.ExtraDisabled) && ct.ExtraDisabled[i] {
			continue
		}
		act := ""
		if i < len(ct.ExtraAction) {
			act = ct.ExtraAction[i]
		}
		if denies(act) && matchedRegex(p, ua) {
			return true
		}
	}
	upstreamDisabled := map[string]bool{}
	for _, p := range n.SearchBots.UpstreamDisabled {
		upstreamDisabled[strings.TrimSpace(p)] = true
	}
	for cat, entries := range classify.UpstreamRescueList() {
		if classify.ResolveGroupMode(cat, n.SearchBots.UpstreamGroupMode) != classify.GroupModeBlack {
			continue
		}
		if !denies(n.SearchBots.UpstreamGroupAction[cat]) {
			continue
		}
		for _, e := range entries {
			if !upstreamDisabled[e.Pattern] && matchedRegex(e.Pattern, ua) {
				return true
			}
		}
	}
	return false
}

// pickValidBV returns the first `_bv` cookie value on the request that
// verifies against the configured secret / validity windows; "" if none do.
//
// Why iterate: r.Cookie("_bv") only returns the first match, and browsers
// can carry duplicate `_bv` entries (= stale cookie at a different path /
// domain shadowing the freshly-set one).  Stopping at the first match
// would lock a legitimate visitor into a permanent challenge loop after
// the stale cookie sorts ahead of the new one in the Cookie header.  The
// matching nginx C plugin does the same iteration in
// ngx_unmask_bv_kind_compute.
// pickValidBV returns the first _bv that verifies for this ip+host, together
// with the kind of the ENTRY that actually verified -- "captcha", "rebind" or
// "pow".
//
// The kind has to come from the matching entry, not from the cookie as a
// whole.  A _bv carries one signed entry per address the client has been seen
// on, joined by "~", so counting dots across the whole value answers a
// different question: a real cookie observed in production reads
// "<3-seg>.rebind~<4-seg>.pow2" -- five dots, neither form -- and the caller
// used to read that as a CAPTCHA pass no matter which half let the request
// through.  MatchingEntryKind runs the same any-match the gate does and
// reports the entry that won.
func pickValidBV(r *http.Request, cfg settings.Settings, ip, site string) (string, string) {
	ch := cfg.Challenge.Resolve(site)
	host := requestHost(r) // must match the host the cookie was issued for
	for _, c := range r.Cookies() {
		if c.Name != "_bv" {
			continue
		}
		// Upper bound generous enough for a full 16-entry "~"-list of per-IP
		// signatures (~35 bytes each); MatchingEntryKind any-matches the entries.
		if c.Value == "" || len(c.Value) > 1024 {
			continue
		}
		if kind, ok := cookies.MatchingEntryKind(c.Value, cfg.Secret.BVSecret, ip, host,
			ch.PowCookieValidSecondsResolved(),
			ch.CaptchaCookieValidSecondsResolved(),
			ch.ResolvedPowDifficulty()); ok {
			return c.Value, normalizeBVKind(kind)
		}
	}
	return "", ""
}

// normalizeBVKind maps the cookie package's wire words onto the counter names
// the dashboard aggregates on: the 4-segment form signs itself "pow2" (the
// marker that distinguishes it from a retired scheme) but has always been
// counted as "pow".  An unrecognized kind passes through rather than being
// flattened -- a newer admin minting a kind this build has not heard of should
// show up as itself in the counters, not as a wrong one.
func normalizeBVKind(kind string) string {
	if kind == "pow2" {
		return "pow"
	}
	return kind
}
