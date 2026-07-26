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
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/classify"
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
	ua := firstNonEmpty(
		r.Header.Get("X-Original-UA"),
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
	bvCookie := pickValidBV(r, cfg, ip, site)
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
		case bvOK:
			// 4 seg (= 3 dots) → PoW, 3 seg (= 2 dots) → CAPTCHA.
			if strings.Count(bvCookie, ".") == 3 {
				action, reason, status = "pass", "bv-pow", http.StatusOK
			} else {
				action, reason, status = "pass", "bv-captcha", http.StatusOK
			}
		case isSearchBotUA(ua, ja4Action, cfg.Nginx, matchers.rangeVerifiedUA):
			// Search / AI crawler rescue.  Must win over geo / protected / ja4 /
			// honeypot exactly like native's is_search_bot exemption, else
			// crawlers without an IP-range preset (ClaudeBot / YandexBot /
			// Bytespider) get wrongly blocked = the ranking accident this
			// project exists to prevent.  Range-verified vendors (Googlebot,
			// bingbot, GPTBot, ...) are excluded from the UA rescue here and
			// pass via the bypass-IP veto below instead (see uarange.go).
			action, reason, status = "pass", "ua:search_ai", http.StatusOK
		case matchers.ipBypass.Match(ip):
			action, reason, status = "pass", "bypass:ip", http.StatusOK
		case matchPath(uri, matchers.bypass):
			action, reason, status = "pass", "bypass:path", http.StatusOK
		default:
			// (3) Gating axes: collect, take max severity (ban already handled).
			decisions := make([]axisDecision, 0, 6)
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
			if d, ok := honeypotDecide(r.Context(), uri, matchers, cfg, h.BanMgr, ip); ok {
				decisions = append(decisions, d)
			}
			if d, ok := protectedDecide(uri, matchers, cfg, site); ok {
				decisions = append(decisions, d)
			}
			if d, ok := ja4Decide(ja4Action, ja4Verdict); ok {
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
	zone := cfg.RateLimit.ResolveZone(uri, site)
	chMode := zone.ResolvedChallengeMode()
	rlHit := false
	rlCount := 0
	rlAllowance := 0
	// A valid _bv (already passed a challenge) exempts the client from
	// CHALLENGE-mode rate-limits -- re-challenging someone who just proved
	// human is pointless.  A "deny" zone is different: it is a HARD CAP, so a
	// human who passed CAPTCHA must NOT buy a pass past it by flooding.  Only
	// trusted sources (bypass IP / verified search bot / signed agent) stay
	// exempt from a deny zone.
	bvExemptFromCount := strings.HasPrefix(reason, "bv-") && chMode != settings.RateChallengeDeny
	shouldCount := h.RateLimiter != nil &&
		!bvExemptFromCount &&
		reason != "bypass:ip" &&
		reason != "bypass:path" &&
		reason != "ua:search_ai" && // never rate-limit rescued crawlers (= ranking accidents on large crawls; mirrors native's empty $rate_limit_key for is_search_bot)
		!strings.HasPrefix(reason, "crawler:verified") && // rDNS-verified crawlers are as trusted as a bypass IP

		!strings.HasPrefix(reason, "signed_agent:") && // verified Web Bot Auth agents aren't rate-limited
		!strings.HasPrefix(reason, "privacy_pass:") && // attested PAT clients aren't rate-limited
		action != "block"
	if shouldCount {
		// Compose the rate-limit counter key from the configured Key kind.
		// Mirrors the nginx side's $rate_limit_key map so a request is
		// counted the same way regardless of native vs forward-auth mode.
		var keyBase string
		switch cfg.RateLimit.ResolvedKey() {
		case settings.RateLimitKeyJA4:
			keyBase = ja4
		case settings.RateLimitKeyIPAndJA4:
			keyBase = ip + "|" + ja4
		default:
			keyBase = ip
		}
		key := keyBase + "|" + zone.Name
		res := h.RateLimiter.Hit(key, ratelimit.Spec{
			RequestsPerMin: zone.RequestsPerMin,
			Burst:          zone.Burst,
			WindowSec:      zone.ResolvedWindowSec(),
		})
		rlCount = res.Count
		rlAllowance = res.Allowance
		if res.Hit {
			rlHit = true
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
	observeOnly := cfg.Challenge.Resolve(site).ObserveOnly && (action == "challenge" || action == "block")
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
	//   "captcha"          : reason="bv-captcha" (= 3-seg _bv HMAC OK)
	//   "pow"              : reason="bv-pow"     (= 4-seg _bv SHA-256 OK)
	//   "challenge_served" : action=challenge or block
	//   ""                 : no signals tripped, total only +1
	if h.NginxLog != nil {
		// bvKind is the RAW _bv kind ("captcha"/"pow"/""), before the
		// challenge_served alias -- the HLL pass bucket counts only a genuine
		// cookie, so it must not see the alias.
		bvKind := ""
		switch reason {
		case "bv-captcha":
			bvKind = "captcha"
		case "bv-pow":
			bvKind = "pow"
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
		h.NginxLog.BumpTrafficHLL(site, ip, fc, bvKind)
		h.NginxLog.BumpCountry(site, ip, kind)
		// Per-IP CAPTCHA-cookie reuse ranking.  Pass the raw bvKind (not the
		// challenge_served alias) so only a genuine reused CAPTCHA cookie is
		// counted; bumpCookieIP no-ops unless bvKind=="captcha".
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
	banMgr *ban.Manager, ip string) (axisDecision, bool) {
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
			"auth_request: hit "+truncateAt(uri, 80), "", presetAct)
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

// protectedDecide fires when the URI matches a protected-paths regex.
// The chain is the rate-limit challenge mode default (= "pow_then_captcha"
// fallback when unset).  site selects the per-site rate-limit record so a
// site that overrides ChallengeMode is honored.
func protectedDecide(uri string, matchers pathMatchers, cfg settings.Settings, site string) (axisDecision, bool) {
	if !matchPath(uri, matchers.protected) {
		return axisDecision{}, false
	}
	// Reuse the rate-limit chain mode as the protected-path default since
	// the protected tab does not yet expose its own chMode picker.
	act := strings.TrimSpace(cfg.RateLimit.Default.ChallengeMode)
	if !settings.IsValidRateChallengeMode(act) {
		act = settings.RateChallengePoWThenCaptcha
	}
	if act == settings.RateChallengeDeny {
		return axisDecision{sev: sevDeny, reason: "protected-path:deny"}, true
	}
	s := severityFromAction(act)
	return axisDecision{sev: s, reason: "protected-path", chMode: chModeFromSeverity(s)}, true
}

// ja4Decide returns a challenge decision when the JA4 verdict says "bot".
// Severity is captcha_only (= JA4 bot is a strong signal so the chain
// skips PoW and goes straight to CAPTCHA, matching the legacy semantics).
func ja4Decide(ja4Action, ja4Verdict string) (axisDecision, bool) {
	if ja4Action != "bot" {
		return axisDecision{}, false
	}
	return axisDecision{
		sev:    sevCaptchaOnly,
		reason: "ja4:" + ja4Verdict,
		chMode: settings.RateChallengeCaptchaOnly,
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
	if listed, category := lookupUAListed(ua, cfg.Nginx); listed != "" && category == "challenge" {
		// The black-list chain is the operator's ChallengeTargets.DefaultAction
		// (ua-filter tab picker), keeping this axis in sync with native
		// ServeChallenge.  Unset keeps the historical fixed captcha_only.
		act := strings.TrimSpace(cfg.Nginx.ChallengeTargets.DefaultAction)
		if !settings.IsValidRateChallengeMode(act) {
			act = settings.RateChallengeCaptchaOnly
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
	if listed, category := lookupUAListed(ua, n); listed != "" && category == "search_ai" {
		return true
	}
	return false
}

// --- helpers ---

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

	// bypass paths: enabled presets + per-site rows from ResolvePaths.
	//
	// Pattern convention: BypassPathRule.Pattern is a **path-anchored** PCRE
	// regex evaluated against the URI directly (e.g., `^/api/`).  We compile
	// it as-is with a case-insensitive flag; no anchor manipulation, matching
	// what the nginx renderer feeds into `map $request_uri ...`.
	//
	// Preset resolution: per-preset DefaultOn + operator deviations via the
	// shared EffectiveBypassPathPresets, and the same SeenVersion NEW gate the
	// renderer applies — so admin's in-memory check agrees with the nginx
	// config it produced (a preset added by an upgrade stays inert on both
	// paths until the operator has seen it).
	enabledBP := nginxconf.EffectiveBypassPathPresets(n.BypassPaths.EnabledPresets, n.BypassPaths.DisabledPresets)
	for _, g := range nginxconf.BypassPathPresetGroups {
		if !enabledBP[g.ID] {
			continue
		}
		if nginxconf.PresetIsNew(n.SeenVersion, g.AddedIn) {
			continue
		}
		for _, r := range g.Rules {
			if r.Site != "" && r.Site != site {
				continue
			}
			if re := compileCachedRe("(?i)" + r.Pattern); re != nil {
				pm.bypass = append(pm.bypass, re)
			}
		}
	}
	for _, row := range n.BypassPaths.ResolvePaths(site) {
		if row.Disabled {
			continue
		}
		if re := compileCachedRe("(?i)" + row.Path); re != nil {
			pm.bypass = append(pm.bypass, re)
		}
	}

	// Per-axis exempt paths (no presets).  Same compile convention as bypass
	// paths; each list is matched in the decision's default case to skip ONLY
	// its own axis (geoDecide or asnDecide).
	compileExemptRows := func(rows []settings.BypassPath) (out []*regexp.Regexp) {
		for _, row := range rows {
			if row.Disabled {
				continue
			}
			if re := compileCachedRe("(?i)" + row.Path); re != nil {
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
	// active-set logic (OptIn / Disabled / Enabled / SeenVersion) mirrors
	// render.go + nginxconf.ResolveHoneypotAction so all three modes agree on
	// which presets are live -- previously this scan honored only
	// DisabledPresets, silently activating OptIn presets (e.g. sql-injection)
	// the operator never enabled.
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
		if nginxconf.PresetIsNew(n.SeenVersion, g.AddedIn) {
			continue
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
		if disabled[g.ID] {
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
// challenge_targets presets / extras, return the listed name +
// category.  Unregistered -> "" / "".
//
// category:
//
//	"search_ai"  : matched SearchBots (= normally rescued)
//	"challenge"  : matched ChallengeTargets (= normally blocked)
//	""           : matched neither (= normal human handling -> show the button)
func lookupUAListed(ua string, n settings.Nginx) (listed, category string) {
	if ua == "" {
		return "", ""
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
			return "extra", "search_ai"
		}
	}
	// ChallengeTargets: the block list (= curl / Python-Requests / Headless etc.)
	disabledCT := map[string]bool{}
	for _, id := range n.ChallengeTargets.DisabledPresets {
		disabledCT[strings.TrimSpace(id)] = true
	}
	for _, g := range nginxconf.ChallengeTargetGroups {
		if disabledCT[g.ID] {
			continue
		}
		for _, p := range g.Patterns {
			if matchedRegex(p, ua) {
				return g.ID, "challenge"
			}
		}
	}
	for i, p := range n.ChallengeTargets.Extra {
		if i < len(n.ChallengeTargets.ExtraDisabled) && n.ChallengeTargets.ExtraDisabled[i] {
			continue
		}
		if matchedRegex(p, ua) {
			return "extra", "challenge"
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
				return cat, "challenge"
			}
		}
	}
	return "", ""
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
func pickValidBV(r *http.Request, cfg settings.Settings, ip, site string) string {
	ch := cfg.Challenge.Resolve(site)
	host := requestHost(r) // must match the host the cookie was issued for
	for _, c := range r.Cookies() {
		if c.Name != "_bv" {
			continue
		}
		// Upper bound generous enough for a full 16-entry "~"-list of per-IP
		// signatures (~35 bytes each); cookies.Verify any-matches the entries.
		if c.Value == "" || len(c.Value) > 1024 {
			continue
		}
		if cookies.Verify(c.Value, cfg.Secret.BVSecret, ip, host,
			ch.PowCookieValidSecondsResolved(),
			ch.CaptchaCookieValidSecondsResolved(),
			ch.ResolvedPowDifficulty()) {
			return c.Value
		}
	}
	return ""
}
