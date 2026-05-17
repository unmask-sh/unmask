// Core of auth_request mode.
//
// Flow:
//   client -> HTTP server (= nginx / Apache / Caddy / etc.)
//                       | subrequest (= auth_request / forward_auth / ext_authz)
//                       v
//          /unmask/api/check  <- this endpoint
//                       |
//                       +-> 200 OK         : let through (= forward normally)
//                           401 Unauthorized: challenge needed (= server redirects to /unmask/challenge/)
//                           403 Forbidden   : block (= persistent BAN / honeypot trip)
//
// Inputs from the HTTP server come as headers:
//   X-Original-URI    original request path + query
//   X-Original-IP     client IP (= equivalent to nginx/Apache's $remote_addr)
//   X-Original-UA     User-Agent
//   X-Original-Host   Host header
//   X-Unmask-Site     (= optional) multi-site identifier
//   Cookie            client cookies including _bv / _br (= passed by the server)
//
// Response headers:
//   X-Unmask-Action   pass | challenge | block
//   X-Unmask-Reason   human-readable reason (e.g. "ban:honeypot", "ua:user_dev")
package handlers

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// AuthCheck: GET / POST /unmask/api/check (= auth_request endpoint).
//
// nginx's auth_request is GET, Caddy's forward_auth is GET, Apache's
// ProxyPass + auth is GET, Envoy ext_authz is POST.  Accept all.
func (h *Handler) AuthCheck(w http.ResponseWriter, r *http.Request) {
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
	site := strings.TrimSpace(r.Header.Get("X-Unmask-Site"))
	if site == "" {
		site = defaultSite
	}
	bvCookie := readCookieMax(r, "_bv", 256)
	// The old _br cookie (= the previous transient PoW marker) is gone.
	// In the current design, the PoW-passed cookie is the 4-seg _bv
	// ("day.sig.target.flags").  It surfaces in reason as "bv-pow".

	cfg := h.snapshotSettings()

	// JA4 fingerprint (= obtained from the TLS handshake.  Usable on
	// the auth_request path even without the nginx module, as long as
	// GCP LB etc. delivers it via X-Client-JA4).
	// Anti-spoofing: only accept the header when the source IP matches
	// a user-configured trusted LB.  Headers from non-trusted sources
	// (= direct access etc.) are dropped (= treated as "").
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	if ja4 == "" {
		ja4 = strings.TrimSpace(r.Header.Get("X-Original-JA4"))
	}
	if ja4 != "" {
		if trusted, _ := nginxconf.IsTrustedLBIP(ip, cfg.Nginx); !trusted {
			ja4 = ""
		}
	}

	matchers := h.bypassMatchers(cfg.Nginx)
	ja4Verdict, ja4Action := matchJA4(ja4, cfg.Nginx)

	action := "pass"
	reason := "ok"
	status := http.StatusOK

	// 2. Decision chain.  Order matters.
	//   bypass (= ip/path) → _bv cookie pass → honeypot → ban → protected → ja4 bot → UA classify
	// _bv runs before honeypot/ban so an operator who already cleared a
	// CAPTCHA can pass even if the IP is later flagged.
	bvOK := bvCookie != "" && cookies.Verify(bvCookie, cfg.Secret.BVSecret, ip, cfg.Challenge.CookieValidDaysCeil(), cfg.Challenge.ResolvedPowDifficulty())
	// honeypotChMode: chain to surface to the challenge JS when the
	// honeypot case takes the challenge branch (= not deny).  Pulled out
	// here so the response-header block below can read it after the switch.
	honeypotChMode := ""
	switch {
	case isBypassIP(ip, cfg.Nginx.BypassIPs):
		action, reason, status = "pass", "bypass:ip", http.StatusOK

	case matchPath(uri, site, matchers.bypass):
		action, reason, status = "pass", "bypass:path", http.StatusOK

	case bvOK:
		// 3-seg = CAPTCHA pass, 4-seg = PoW pass.
		if strings.Count(bvCookie, ".") == 3 {
			action, reason, status = "pass", "bv-pow", http.StatusOK
		} else {
			action, reason, status = "pass", "bv-captcha", http.StatusOK
		}

	case matchPathSimple(uri, matchers.honeypot):
		// honeypot trip -> always record a BAN entry.  Response branch
		// depends on Honeypot.DefaultAction:
		//   "deny"                   : 403 block (= "trap = instant block, no recovery").
		//   pow_only / pow_then_captcha / captcha_only / empty
		//                            : 401 challenge.  Solve → _bv cookie
		//                              → bypasses the BAN on later requests
		//                              because _bv verify runs first.
		if h.BanMgr != nil {
			h.BanMgr.AddWithSource(r.Context(), ip, "", "honeypot",
				"auth_request: hit "+truncateAt(uri, 80), "")
		}
		act := strings.TrimSpace(cfg.Nginx.Honeypot.DefaultAction)
		if act == settings.RateChallengeDeny {
			action, reason, status = "block", "honeypot:deny", http.StatusForbidden
		} else {
			if !settings.IsValidRateChallengeMode(act) {
				act = settings.RateChallengePoWThenCaptcha
			}
			honeypotChMode = act
			action, reason, status = "challenge", "honeypot:"+act, http.StatusUnauthorized
		}

	case h.BanMgr != nil && banSrcCheck(r.Context(), h.BanMgr, ip, cfg.Nginx.Honeypot.DefaultAction, &honeypotChMode, &action, &reason, &status):
		// (decision was filled in by banSrcCheck — honeypot-derived bans
		// route to challenge unless DefaultAction=deny; other sources stay 403)

	case false: // (placeholder so the next branch keeps its case form)
		_ = bvCookie
		// Branch reason by cookie format:
		//   3 segments "<day>.<HMAC>.<kind>"               -> CAPTCHA path (= bv column)
		//        2 dots
		//   4 segments "<day>.<djb2>.<target>.<flags>"     -> PoW path     (= bp column)
		//        3 dots
		if strings.Count(bvCookie, ".") == 3 {
			action, reason, status = "pass", "bv-pow", http.StatusOK
		} else {
			action, reason, status = "pass", "bv-captcha", http.StatusOK
		}

	case matchPathSimple(uri, matchers.protected):
		action, reason, status = "challenge", "protected-path", http.StatusUnauthorized

	case ja4Action == "bot":
		// JA4 verdict bot = real spoofed bot.  Skip PoW -> straight to CAPTCHA.
		action, reason, status = "challenge", "ja4:"+ja4Verdict, http.StatusUnauthorized

	default:
		// Final decision via UA classification.  Search bots / AI bots
		// are let through.  Other categories defer to the 動作モード
		// (Global) axis so the no-match path matches what the serveBot-
		// Challenge handler does (= Known/UnknownUAAction with strict
		// "pow_only" fallback).
		switch classify.IsBot(ua, ja4Action).String() {
		case "search_ai":
			action, reason, status = "pass", "ua:search_ai", http.StatusOK
		default:
			// Look up UA against ChallengeTargetGroups first; a target
			// hit always challenges regardless of Global (= explicit
			// black-list beats the no-match default).
			listed, category := lookupUAListed(ua, cfg.Nginx)
			if listed != "" && category == "challenge" {
				action, reason, status = "challenge", "ua:target:"+listed, http.StatusUnauthorized
				break
			}
			// Pick the Global axis based on whether the UA looks like a
			// real browser.  Empty = "pow_only" (= strict default,
			// matches serveBotChallenge fallback).
			var pick string
			if classify.IsKnownBrowser(ua) {
				pick = cfg.Global.KnownBrowserAction
			} else {
				pick = cfg.Global.UnknownUAAction
			}
			if pick == "" {
				pick = cfg.Global.DefaultAction
			}
			if pick == "" {
				pick = "pow_only"
			}
			if pick == "pass" {
				if classify.IsKnownBrowser(ua) {
					action, reason, status = "pass", "human", http.StatusOK
				} else {
					action, reason, status = "pass", "ua:unknown", http.StatusOK
				}
			} else {
				// pow_only / pow_then_captcha / captcha_only / deny — all
				// surface as challenge here; the chMode value flows
				// through serveBotChallenge via the same Global axis.
				tag := "ua:unknown"
				if classify.IsKnownBrowser(ua) {
					tag = "ua:browser"
				}
				action, reason, status = "challenge", tag+":"+pick, http.StatusUnauthorized
			}
		}
	}

	// 2.5. rate-limit.  Don't count requests already decided by bypass /
	// cookie pass / honeypot / ban (= respect existing fast path /
	// final block).  Otherwise count, and on threshold exceedance,
	// promote to challenge + emit the zone / challenge_mode in response
	// headers so nginx can transfer them into the error_page query.
	zone := cfg.RateLimit.ResolveZone(uri)
	chMode := zone.ResolvedChallengeMode()
	rlHit := false
	rlCount := 0
	rlAllowance := 0
	shouldCount := h.RateLimiter != nil &&
		!strings.HasPrefix(reason, "bv-") &&
		reason != "bypass:ip" &&
		reason != "bypass:path" &&
		action != "block"
	if shouldCount {
		key := ip + "|" + ja4 + "|" + zone.Name
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
	observeOnly := cfg.Challenge.ObserveOnly && (action == "challenge" || action == "block")
	wouldBeAction := action
	wouldBeReason := reason

	// 3. Record the event (= flow into dashboard / bot-hunt tab).
	// Insert with phase=check for every action.  In auth_request mode
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
	//   "pow"              : reason="bv-pow"     (= 4-seg _bv djb2 OK)
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

// banSrcCheck: probe BAN list, branch on source, fill in action/reason/status.
// Returns true when a live ban entry covers ip (= caller's switch should
// treat that case as matched).  Honeypot-derived bans honor
// Honeypot.DefaultAction (= deny → 403, anything else → challenge so the
// visitor can recover via CAPTCHA → _bv).  Other sources stay 403.
func banSrcCheck(ctx context.Context, mgr *ban.Manager, ip, honeypotAct string,
	chModeOut, actionOut, reasonOut *string, statusOut *int) bool {
	src, banned := mgr.IsBannedSource(ctx, ip, "")
	if !banned {
		return false
	}
	if src == "honeypot" {
		act := strings.TrimSpace(honeypotAct)
		if act == settings.RateChallengeDeny {
			*actionOut, *reasonOut, *statusOut = "block", "ban:honeypot:deny", http.StatusForbidden
		} else {
			if !settings.IsValidRateChallengeMode(act) {
				act = settings.RateChallengePoWThenCaptcha
			}
			*chModeOut = act
			*actionOut, *reasonOut, *statusOut = "challenge", "ban:honeypot:"+act, http.StatusUnauthorized
		}
	} else {
		*actionOut, *reasonOut, *statusOut = "block", "ban:"+src, http.StatusForbidden
	}
	return true
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

func isBypassIP(ip string, list []string) bool {
	if ip == "" {
		return false
	}
	for _, s := range list {
		if strings.TrimSpace(s) == ip {
			return true
		}
	}
	return false
}

// --- Regex matcher cache (= recompile only when settings change) ---

type pathMatchers struct {
	// bypass: site-restricted variant.  site == "" matches every site;
	// otherwise only when site equals.
	bypass    []siteRegex
	honeypot  []*regexp.Regexp
	protected []*regexp.Regexp
}

type siteRegex struct {
	site string // "" = every site
	re   *regexp.Regexp
}

// bypassMatchersCache: reused until the settings identity changes.
var (
	matchersMu     sync.Mutex
	cachedNginxPtr *settings.Nginx
	cachedMatchers pathMatchers
)

// bypassMatchers: build the regex list from settings.  Reuse the cache for the same pointer.
func (h *Handler) bypassMatchers(n settings.Nginx) pathMatchers {
	matchersMu.Lock()
	defer matchersMu.Unlock()
	if cachedNginxPtr == &n { // normally false (= a local copy has a different pointer)
		return cachedMatchers
	}
	pm := pathMatchers{}

	// bypass paths: enabled presets + enabled extras.
	disabledBP := toSet(n.BypassPaths.DisabledPresets)
	for _, g := range nginxconf.BypassPathPresetGroups {
		if disabledBP[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			if re, err := regexp.Compile("(?i)" + r.Pattern); err == nil {
				pm.bypass = append(pm.bypass, siteRegex{site: r.Site, re: re})
			}
		}
	}
	for i, p := range n.BypassPaths.Extra {
		if i < len(n.BypassPaths.ExtraDisabled) && n.BypassPaths.ExtraDisabled[i] {
			continue
		}
		if re, err := regexp.Compile("(?i)" + p); err == nil {
			site := ""
			if i < len(n.BypassPaths.ExtraSite) {
				site = n.BypassPaths.ExtraSite[i]
			}
			pm.bypass = append(pm.bypass, siteRegex{site: site, re: re})
		}
	}

	// honeypot: enabled presets + extras.  No site concept.
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
	for _, p := range n.Honeypot.Extra {
		if re, err := regexp.Compile("(?i)" + p); err == nil {
			pm.honeypot = append(pm.honeypot, re)
		}
	}

	// protected paths: presets + extras.  No site concept.
	disabledPP := toSet(n.ProtectedPaths.DisabledPresets)
	neverSavedPP := n.ProtectedPaths.DisabledPresets == nil
	for _, g := range nginxconf.ProtectedPathPresetGroups {
		if neverSavedPP || disabledPP[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			if re, err := regexp.Compile("(?i)" + r.Pattern); err == nil {
				pm.protected = append(pm.protected, re)
			}
		}
	}
	for i, p := range n.ProtectedPaths.Extra {
		if i < len(n.ProtectedPaths.ExtraDisabled) && n.ProtectedPaths.ExtraDisabled[i] {
			continue
		}
		if re, err := regexp.Compile("(?i)" + p); err == nil {
			pm.protected = append(pm.protected, re)
		}
	}

	cachedNginxPtr = &n
	cachedMatchers = pm
	return pm
}

func matchPath(uri, site string, list []siteRegex) bool {
	for _, sr := range list {
		if sr.site != "" && sr.site != site {
			continue
		}
		if sr.re.MatchString(uri) {
			return true
		}
	}
	return false
}

func matchPathSimple(uri string, list []*regexp.Regexp) bool {
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
//   "search_ai"  : matched SearchBots (= normally rescued)
//   "challenge"  : matched ChallengeTargets (= normally blocked)
//   ""           : matched neither (= normal human handling -> show the button)
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
	return "", ""
}
