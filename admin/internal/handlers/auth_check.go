// Core of forward-auth mode.
//
// Flow:
//
//	client -> HTTP server (= nginx / Apache / Caddy / etc.)
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
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/webbotauth"
)

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
// nginx's auth_request is GET, Caddy's forward_auth is GET, Apache's
// ProxyPass + auth is GET, Envoy ext_authz is POST.  Accept all.
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
	cfg := h.snapshotSettings()
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

	matchers := h.bypassMatchers(cfg.Nginx, site)
	ja4Verdict, ja4Action := matchJA4(ja4, cfg.Nginx)

	action := "pass"
	reason := "ok"
	status := http.StatusOK

	// Web Bot Auth (RFC 9421) is an explicit veto-pass axis: a valid signed
	// request joins the search-bot rescue path instead of running through
	// the score axes.  Verify up-front so the result is available to the
	// switch below + can be logged in the event payload regardless of which
	// axis ended up winning (= operator visibility).
	var wbaResult webbotauth.Result
	if cfg.Nginx.WebBotAuth.Enabled && h.WebBotAuth != nil && r.Header.Get("Signature-Input") != "" {
		wbaResult = h.WebBotAuth.Verify(r.Context(), r)
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
	if d, ok := banDecide(r.Context(), h.BanMgr, ip, cfg); ok {
		if d.sev == sevDeny {
			action, reason, status = "block", d.reason, http.StatusForbidden
		} else {
			action, reason, status = "challenge", d.reason, http.StatusUnauthorized
		}
		honeypotChMode = d.chMode
	} else {
		switch {
		// (2) Veto-passes, in native order.  Each is a hard pass that wins over
		// the gating axes below.
		case wbaResult.OK && cfg.Nginx.WebBotAuth.IsOperatorAllowed(wbaResult.Operator):
			// Signed agent verified — same trust level as the IP allowlist.
			// Reason carries the operator host so dashboards can break it down.
			action, reason, status = "pass", "signed_agent:"+wbaResult.Operator, http.StatusOK
		case bvOK:
			// 4 seg (= 3 dots) → PoW, 3 seg (= 2 dots) → CAPTCHA.
			if strings.Count(bvCookie, ".") == 3 {
				action, reason, status = "pass", "bv-pow", http.StatusOK
			} else {
				action, reason, status = "pass", "bv-captcha", http.StatusOK
			}
		case isSearchBotUA(ua, ja4Action, cfg.Nginx):
			// Search / AI crawler rescue.  Must win over geo / protected / ja4 /
			// honeypot exactly like native's is_search_bot exemption, else
			// crawlers without an IP-range preset (ClaudeBot / YandexBot /
			// Applebot / Amazonbot / Bytespider) get wrongly blocked = the
			// ranking accident this project exists to prevent.
			action, reason, status = "pass", "ua:search_ai", http.StatusOK
		case matchers.ipBypass.Match(ip):
			action, reason, status = "pass", "bypass:ip", http.StatusOK
		case matchPath(uri, matchers.bypass):
			action, reason, status = "pass", "bypass:path", http.StatusOK
		default:
			// (3) Gating axes: collect, take max severity (ban already handled).
			decisions := make([]axisDecision, 0, 5)
			if d, ok := h.geoDecide(ip, cfg); ok {
				decisions = append(decisions, d)
			}
			if d, ok := honeypotDecide(uri, matchers, cfg, h.BanMgr, r.Context(), ip); ok {
				decisions = append(decisions, d)
			}
			if d, ok := protectedDecide(uri, matchers, cfg, site); ok {
				decisions = append(decisions, d)
			}
			if d, ok := ja4Decide(ja4Action, ja4Verdict); ok {
				decisions = append(decisions, d)
			}
			if d, ok := uaDecide(ua, ja4Action, cfg); ok {
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
	shouldCount := h.RateLimiter != nil &&
		!strings.HasPrefix(reason, "bv-") &&
		reason != "bypass:ip" &&
		reason != "bypass:path" &&
		reason != "ua:search_ai" && // never rate-limit rescued crawlers (= ranking accidents on large crawls; mirrors native's empty $rate_limit_key for is_search_bot)
		!strings.HasPrefix(reason, "signed_agent:") && // verified Web Bot Auth agents aren't rate-limited
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
		kind := ""
		switch reason {
		case "bv-captcha":
			kind = "captcha"
		case "bv-pow":
			kind = "pow"
		}
		if kind == "" && (action == "challenge" || action == "block") {
			kind = "challenge_served"
		}
		h.NginxLog.Bump(site, kind)
		// Crawler funnel: in forward-auth mode no access-log line is emitted,
		// so feed the crawler aggregate here.  served = the request did not
		// pass straight through.
		h.NginxLog.BumpCrawler(ua, action != "pass")
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
func (h *Handler) geoDecide(ip string, cfg settings.Settings) (axisDecision, bool) {
	if h.IPGeo == nil || !h.IPGeo.Loaded() {
		return axisDecision{}, false
	}
	country := strings.ToUpper(strings.TrimSpace(h.IPGeo.LookupInfo(ip).Country))
	return geoDecideForCountry(country, cfg.Nginx.Geo)
}

// geoDecideForCountry: pure decision given a resolved country string.
//   - empty country -> silent (= mmdb miss / private IP, fail-open)
//   - resolved action "skip" or empty -> silent (= geo intentionally
//     declines to act for this country; lets other axes decide)
//   - "deny" -> sevDeny
//   - challenge-mode action -> matching severity, chMode set
func geoDecideForCountry(country string, geo settings.GeoConfig) (axisDecision, bool) {
	if country == "" {
		return axisDecision{}, false
	}
	act := geo.ResolvedDefaultAction()
	rule := geo.LookupRule(country)
	if rule != nil && strings.TrimSpace(rule.Action) != "" {
		act = rule.Action
	}
	switch act {
	case "", settings.GeoActionSkip:
		return axisDecision{}, false
	case settings.GeoActionDeny:
		return axisDecision{sev: sevDeny, reason: "geo:" + country + ":deny"}, true
	default:
		s := severityFromAction(act)
		return axisDecision{sev: s, reason: "geo:" + country + ":" + act, chMode: chModeFromSeverity(s)}, true
	}
}

// honeypotDecide returns a decision when the URI matches a honeypot path.
// Side effect: adds an entry to the persistent BAN list (= regardless of
// whether honeypot wins the max — the trap counts even if a stronger axis
// is the visible verdict).
func honeypotDecide(uri string, matchers pathMatchers, cfg settings.Settings,
	banMgr *ban.Manager, ctx context.Context, ip string) (axisDecision, bool) {
	if !matchPath(uri, matchers.honeypot) {
		return axisDecision{}, false
	}
	if banMgr != nil {
		banMgr.AddWithSource(ctx, ip, "", "honeypot",
			"auth_request: hit "+truncateAt(uri, 80), "")
	}
	act := strings.TrimSpace(cfg.Nginx.Honeypot.DefaultAction)
	if act == settings.RateChallengeDeny {
		return axisDecision{sev: sevDeny, reason: "honeypot:deny"}, true
	}
	if !settings.IsValidRateChallengeMode(act) {
		// Inherit the same chain default as the rate-limit axis so the
		// "default = pow_then_captcha" recommendation holds everywhere.
		act = settings.RateChallengePoWThenCaptcha
	}
	s := severityFromAction(act)
	return axisDecision{sev: s, reason: "honeypot:" + act, chMode: chModeFromSeverity(s)}, true
}

// banDecide consults the persistent BAN list.  Resolution (= mgr lookup) is
// split from the per-source policy so the policy half is table-testable.
func banDecide(ctx context.Context, mgr *ban.Manager, ip string, cfg settings.Settings) (axisDecision, bool) {
	if mgr == nil {
		return axisDecision{}, false
	}
	src, banned := mgr.IsBannedSource(ctx, ip, "")
	if !banned {
		return axisDecision{}, false
	}
	return banDecideFromSource(src, cfg)
}

// banDecideFromSource: pure decision given a ban source string.  Each
// source (= "honeypot" / "manual" / "community_bans") picks its action from
// settings via BansConfig.ResolveAction (= honeypot defers to
// Honeypot.DefaultAction; the others read Bans.ManualDefaultAction /
// Bans.CommunityBansDefaultAction).  Unknown sources hard-deny so a future
// source never silently falls through.
func banDecideFromSource(src string, cfg settings.Settings) (axisDecision, bool) {
	act := cfg.Nginx.Bans.ResolveAction(src, cfg.Nginx.Honeypot.DefaultAction)
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
func uaDecide(ua, ja4Action string, cfg settings.Settings) (axisDecision, bool) {
	switch classify.IsBot(ua, ja4Action).String() {
	case "search_ai":
		return axisDecision{sev: sevPass, reason: "ua:search_ai"}, true
	}
	if listed, category := lookupUAListed(ua, cfg.Nginx); listed != "" && category == "challenge" {
		return axisDecision{
			sev:    sevCaptchaOnly,
			reason: "ua:target:" + listed,
			chMode: settings.RateChallengeCaptchaOnly,
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
	return axisDecision{sev: s, reason: tag + ":" + pick, chMode: chModeFromSeverity(s)}, true
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
func isSearchBotUA(ua, ja4Action string, n settings.Nginx) bool {
	if classify.IsBot(ua, ja4Action).String() == "search_ai" {
		return true
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
	// X-Unmask-Site is operator-set in trusted upstreams (= nginx config
	// `proxy_set_header X-Unmask-Site $unmask_site;`).  But default forward-
	// auth deployments leave that directive commented out, and nginx's
	// proxy_pass_request_headers default forwards client-supplied headers,
	// so accepting it from anyone lets an attacker pick a different site's
	// per-site config (= challenge bypass via observe_only=true, weaker
	// honeypot/bypass/rate-limit zone).  Gate on the peer being a trusted
	// proxy -- same shape as resolveForwardedJA4.
	if peerIsTrustedProxy(r.RemoteAddr, forwardAuthTrustedPeers(cfg)) {
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
// auth_request / Apache mod_lua / Caddy forward_auth / an LB / CDN) is what
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
	if !peerIsTrustedProxy(r.RemoteAddr, forwardAuthTrustedPeers(cfg)) {
		return ""
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

// --- Regex matcher cache (= recompile only when settings change) ---

type pathMatchers struct {
	bypass    []*regexp.Regexp
	honeypot  []*regexp.Regexp
	protected []*regexp.Regexp
	ipBypass  *nginxconf.IPBypassMatcher
}

// bypassMatchersCache: reused until the (settings pointer, site) pair
// changes.  site is part of the key so swapping vhosts mid-process does
// not return a cached compile that was filtered for a different host.
var (
	matchersMu     sync.Mutex
	cachedNginxPtr *settings.Nginx
	cachedSite     string
	cachedMatchers pathMatchers
)

// bypassMatchers: build the per-site regex list from settings.  Uses
// BypassPathsConfig.ResolvePaths(site) / ProtectedPathsConfig.ResolvePaths /
// HoneypotConfig.ResolveURLs so a row's Site filter is honored once, here,
// and the downstream matchers stay site-agnostic.
func (h *Handler) bypassMatchers(n settings.Nginx, site string) pathMatchers {
	matchersMu.Lock()
	defer matchersMu.Unlock()
	if cachedNginxPtr == &n && cachedSite == site { // normally false (= a local copy has a different pointer)
		return cachedMatchers
	}
	pm := pathMatchers{}

	// bypass IPs: preset ranges (Googlebot etc.) + enabled bypass_ips rows,
	// CIDR-aware -- the same allowlist the native geo $is_bypass_ip block bakes
	// in, so forward-auth never challenges a trusted crawler the native path
	// would exempt.
	pm.ipBypass = nginxconf.NewIPBypassMatcher(n)

	// bypass paths: enabled presets + per-site rows from ResolvePaths.
	//
	// Pattern convention: BypassPathRule.Pattern is a **path-anchored** PCRE
	// regex evaluated against the URI directly (e.g., `^/api/`).  We compile
	// it as-is with a case-insensitive flag; no anchor manipulation, matching
	// what the nginx renderer feeds into `map $request_uri ...`.
	//
	// Preset opt-in: only IDs in EnabledPresets activate, matching the
	// renderer so admin's in-memory check agrees with the nginx config it
	// produced.
	enabledBP := toSet(n.BypassPaths.EnabledPresets)
	for _, g := range nginxconf.BypassPathPresetGroups {
		if !enabledBP[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			if r.Site != "" && r.Site != site {
				continue
			}
			if re, err := regexp.Compile("(?i)" + r.Pattern); err == nil {
				pm.bypass = append(pm.bypass, re)
			}
		}
	}
	for _, row := range n.BypassPaths.ResolvePaths(site) {
		if row.Disabled {
			continue
		}
		if re, err := regexp.Compile("(?i)" + row.Path); err == nil {
			pm.bypass = append(pm.bypass, re)
		}
	}

	// honeypot: enabled presets + per-site URLs.
	disabledHP := toSet(n.Honeypot.DisabledPresets)
	for _, g := range nginxconf.HoneypotPresetGroups {
		if disabledHP[g.ID] {
			continue
		}
		for _, p := range g.Patterns {
			if re, err := regexp.Compile("(?i)" + p); err == nil {
				pm.honeypot = append(pm.honeypot, re)
			}
		}
	}
	for _, u := range n.Honeypot.ResolveURLs(site) {
		if u.Disabled {
			continue
		}
		if re, err := regexp.Compile("(?i)" + u.Path); err == nil {
			pm.honeypot = append(pm.honeypot, re)
		}
	}

	// protected paths: presets + per-site rows.
	enabledPP := toSet(n.ProtectedPaths.EnabledPresets)
	for _, g := range nginxconf.ProtectedPathPresetGroups {
		if !enabledPP[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			if re, err := regexp.Compile("(?i)" + r.Pattern); err == nil {
				pm.protected = append(pm.protected, re)
			}
		}
	}
	for _, row := range n.ProtectedPaths.ResolvePaths(site) {
		if row.Disabled {
			continue
		}
		if re, err := regexp.Compile("(?i)" + row.Path); err == nil {
			pm.protected = append(pm.protected, re)
		}
	}

	cachedNginxPtr = &n
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
	// SearchBots: the rescue list (= Googlebot / GPTBot etc.)
	disabledSB := map[string]bool{}
	for _, id := range n.SearchBots.DisabledPresets {
		disabledSB[strings.TrimSpace(id)] = true
	}
	for _, g := range nginxconf.SearchBotGroups {
		if disabledSB[g.ID] {
			continue
		}
		for _, p := range g.Patterns {
			if matchedRegex(p, ua) {
				return g.ID, "search_ai"
			}
		}
	}
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
	for _, c := range r.Cookies() {
		if c.Name != "_bv" {
			continue
		}
		if c.Value == "" || len(c.Value) > 256 {
			continue
		}
		if cookies.Verify(c.Value, cfg.Secret.BVSecret, ip,
			ch.PowCookieValidSecondsResolved(),
			ch.CaptchaCookieValidSecondsResolved(),
			ch.ResolvedPowDifficulty()) {
			return c.Value
		}
	}
	return ""
}
