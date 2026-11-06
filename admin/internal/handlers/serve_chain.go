package handlers

import (
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// serveChainInputs: what ServeChallenge has worked out about a serve by the
// time it picks the chain -- the axis the request was sent here by, and what
// that axis's rule said.
type serveChainInputs struct {
	forceReason string // the axis the serve is attributed to: "none", "protected", "asn", "geo", "honeypot", "reuse_limit", "rate_limit", "ja4_bot", ...
	forceQuery  string // ?_force= on a test route: "pow", "captcha", "pow_then_captcha"; "" elsewhere
	ppMode      string // the protected path's mode, for forceReason "protected"
	netChMode   string // the matched network rule's chain, for "asn" / "geo"
	verdict     string // the JA4 verdict's name, for "ja4_bot"
	uaListed    bool   // the User-Agent matched a challenge target
	uaRowAction string // that row's own chain, when it pinned one
	cbHitKind   string // the community list the client is on; "" when on none
}

// serveChain picks the chain a challenge serve shows: pow_only, captcha_only,
// pow_then_captcha or deny.
//
// It is ServeChallenge's own code, moved out whole so that the order in which
// the tiers override one another can be read, and tested, without the page
// assembly around it.  The order, each step replacing what came before unless
// it says otherwise:
//
//  1. the rate-limit default (the fallback every path starts from);
//  2. the attributed axis's own chain -- the operating mode's pick for a
//     plain serve, the protected path's mode, the network / honeypot / JA4
//     rule's action, the UA black list's default, row, group or preset;
//  3. a community-list hit's action;
//  4. the stale-browser, header-integrity and UA-TLS tiers, none of which
//     softens a deny;
//  5. a custom rule's action (never softening a deny, never a deny itself);
//  6. ?chm= from a wrapper's internal route;
//  7. the backstop: a request the gate will ask a CAPTCHA-grade pass of gets
//     a chain that ends in a CAPTCHA;
//  8. ?_force= on a test route, which wins over all of it.
//
// It reads the request and the settings and writes nothing.
func (h *Handler) serveChain(r *http.Request, in serveChainInputs) string {
	forceReason, forceQuery := in.forceReason, in.forceQuery
	ppMode, netChMode, verdict := in.ppMode, in.netChMode, in.verdict
	uaListed, uaRowAction, cbHitKind := in.uaListed, in.uaRowAction, in.cbHitKind

	chMode := h.cfg().RateLimit.Default.ResolvedChallengeMode()
	if forceReason == "none" {
		// "no-match" path: split the chain by whether the UA looks like
		// a real browser.  Empty (= fresh install, never touched the
		// Operating mode tab) means "strict" — the default protection posture.
		ua := r.Header.Get("User-Agent")
		var pick string
		if classify.IsKnownBrowser(ua) {
			pick = h.cfg().Global.KnownBrowserAction
		} else {
			pick = h.cfg().Global.UnknownUAAction
		}
		if pick == "" {
			pick = "pow_only" // strict default
		}
		if pick != "pass" && settings.IsValidRateChallengeMode(pick) {
			chMode = pick
		}
	}
	if forceReason == "protected" {
		// Mode == action: the per-path mode maps 1:1 to the served chain
		//   pow -> PoW only; captcha -> straight CAPTCHA; pow_then_captcha -> chain.
		// No default-action / rate-limit-linkage override on top (removed in the
		// redesign) -- the mode the operator picked is exactly what gets served.
		chMode = nginxconf.ChModeForProtectedMode(ppMode)
	} else if forceReason == "asn" || forceReason == "geo" {
		// The matched rule's own action, the way honeypot and ja4_bot already
		// serve theirs.  Without this branch the network axis was attributed
		// and then handed the default chain: a rule saying captcha_only was
		// served as pow_then_captcha, because the grade backstop below saw a
		// chain that did not end in a CAPTCHA and escalated it -- which keeps
		// the proof-of-work leg on purpose, and the proof-of-work leg is
		// precisely what an operator picking captcha_only is declining to
		// offer a network whose clients run JavaScript.
		if settings.IsValidRateChallengeMode(netChMode) {
			chMode = netChMode
		}
	} else if forceReason == "honeypot" {
		// The trap's own action (its row, or its preset group), then the tab
		// default -- the same order forward-auth's honeypotDecide resolves, via
		// the same resolver.  This branch used to read only the tab default, so
		// a trap row pinned to captcha_only or deny was honoured behind a load
		// balancer and ignored on native: the per-row picker was decorative on
		// one wire, which is the shape the protected-path redesign removed.
		if act := strings.TrimSpace(h.cfg().Nginx.Honeypot.DefaultAction); act != "" && settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
		// The trapped URI reaches the serve the same way the protected axis
		// resolves its path: the _orig query (apache's lua redirect), else the
		// URI the native rewrite preserved.
		hpURI := strings.TrimSpace(r.URL.Query().Get("_orig"))
		if hpURI == "" {
			hpURI = banProbedOrigPath(r, h.basePath())
		}
		if act, matched := nginxconf.ResolveHoneypotAction(hpURI,
			siteFromRequest(r, h.snapshotSettings()), h.cfg().Nginx); matched &&
			settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
	} else if forceReason == "reuse_limit" {
		// Only a CAPTCHA: a PoW would hand the client one more pass to reuse.
		chMode = settings.RateChallengeCaptchaOnly
	} else if forceReason == "rate_limit" {
		// Native rate zones carry only "you hit a zone", not which ASN/geo rule
		// -- re-derive the client's network from the IP and, if it matches a
		// rate-mode rule, serve that rule's per-rule action instead of the base
		// default (the plumbing this branch used to lack).  A path-zone deny was
		// already short-circuited to serveRateDeny upstream, so only ASN/geo
		// per-rule actions land here; "" (no network rule) leaves chMode alone.
		if act := h.netRateOverageAction(adminClientIP(r, *h.cfg()), *h.cfg()); act != "" && settings.IsValidRateChallengeMode(act) {
			chMode = act
		}
	} else if forceReason == "ja4_bot" {
		// EffectiveJA4BotChain, not the raw resolver: the same effective
		// chain ja4Decide answers checks with and the grade gate demands.
		// Serving anything else for an unconfigured axis could mint the very
		// cookie the gate refuses -- a challenge loop.
		chMode = nginxconf.EffectiveJA4BotChain(verdict, *h.cfg())
	} else if forceReason != "rate_limit" {
		// ChallengeTargets.DefaultAction is the black-list chain (ua-filter
		// tab: "chain used when a black-list UA match triggers a challenge"),
		// not a global default.  Native nginx sends every escalation here as
		// forceReason="none" with no target-vs-plain distinction, so gate the
		// override on the UA actually matching a challenge target (preset /
		// extra / upstream black group).  Ungated it overrode the
		// Operating-mode pick for every plain challenge: with
		// default_action=pow_then_captcha a current-stable Chrome that failed
		// the transparent PoW was walked into the CAPTCHA leg the operator
		// only meant for black-listed UAs.
		if ua := r.Header.Get("User-Agent"); ua != "" {
			if uaListed {
				if act := strings.TrimSpace(h.cfg().Nginx.ChallengeTargets.DefaultAction); act != "" && settings.IsValidRateChallengeMode(act) {
					chMode = act
				}
				// The matched row's own chain, when it pinned one.  Same
				// precedence as the per-preset override below: the more
				// specific rule wins over the list-wide default.
				if settings.IsValidRateChallengeMode(uaRowAction) {
					chMode = uaRowAction
				}
			}
			// Per-group override: scan the UA against the upstream-rescue
			// crawlers resolved to "black" (group-wide or on their own) whose
			// group carries an action override.
			sb := h.cfg().Nginx.SearchBots
			if grpAct := classify.ResolveActionForUA(ua,
				sb.UpstreamGroupMode, sb.UpstreamPatternMode,
				sb.UpstreamGroupAction); grpAct != "" && settings.IsValidRateChallengeMode(grpAct) {
				chMode = grpAct
			}
			// Per-preset override (= ChallengeTargetGroups).  Same
			// inheritance rule: an override on a preset wins over the
			// black-list default.  Skipped presets (= DisabledPresets)
			// take no action, mirroring the nginx render.
			specs := make([]classify.PresetGroupSpec, 0, len(nginxconf.ChallengeTargetGroups))
			for _, g := range nginxconf.ChallengeTargetGroups {
				specs = append(specs, classify.PresetGroupSpec{ID: g.ID, Patterns: g.Patterns})
			}
			disabledTgt := map[string]bool{}
			for _, id := range h.cfg().Nginx.ChallengeTargets.DisabledPresets {
				disabledTgt[id] = true
			}
			// A preset held for upgrade review is inert: it must not steer the
			// challenge chain mode either, matching the decision wires
			// (render.go / auth_check.go).  Without this a held target's
			// per-preset action would still upgrade pow -> captcha/deny for a
			// visitor challenged by another axis.
			for _, g := range nginxconf.ChallengeTargetGroups {
				if nginxconf.EnforcementHeld(h.cfg().Nginx, g.AddedIn) {
					disabledTgt[g.ID] = true
				}
			}
			if preAct := classify.ResolvePresetActionForUA(ua, specs,
				h.cfg().Nginx.ChallengeTargets.PresetAction,
				disabledTgt); preAct != "" && settings.IsValidRateChallengeMode(preAct) {
				chMode = preAct
			}
		}
	}
	// Community-feed chain: the operator's action for a shared-list hit, from
	// the same resolver render.go bakes into the nginx conf and auth_check
	// reads live.  Placed after the per-axis chain so it replaces whatever the
	// base picked -- the action was chosen for exactly this population.
	if cbHitKind != "" {
		chMode = h.cfg().CommunityBans.ResolvedAction()
	}
	// Stale-browser escalation.  A UA whose Chromium-family major is far behind
	// current stable is a headless-scraper tell (the 2026-07-15 incident);
	// serve it the operator's stale screen (default captcha_only) so a
	// PoW-solving headless engine hits the CAPTCHA it cannot cheaply clear.  The
	// stale action REPLACES the base chMode — the operator picked it precisely
	// for these UAs, so "captcha_only" must win even over a base pow_then_captcha
	// (skipping the pointless PoW leg is the intent).  The one thing it must not
	// do is soften a hard deny, so a deny base is left intact.  Safe against
	// exemptions: a bypass-IP / search-bot request never reaches ServeChallenge
	// (native protect.inc only redirects a $final_challenge=1 request here), so
	// monitoring probes are untouched.
	if g := h.cfg().Global; g.StaleBrowserEnabled() && chMode != settings.RateChallengeDeny {
		if ua := r.Header.Get("User-Agent"); classify.IsStaleBrowser(ua, g.CurrentChromeMajorResolved(),
			g.CurrentFirefoxMajorResolved(), g.FirefoxESRMajors(), g.StaleBrowserLagN(), g.FirefoxStaleLagN()) {
			chMode = g.StaleBrowserResolvedAction()
		}
	}
	// Header-integrity escalation (native): the nginx tier only signals "1"
	// with no chMode, so resolve the axis's clamped action here for a request
	// that mismatches.  Same never-soften-a-deny guard as the stale tier.  On
	// the forward-auth path headerDecide already set the reason/chMode, so this
	// only augments the native serve (a direct hit re-checks cheaply).
	if g := h.cfg().Global; chMode != settings.RateChallengeDeny && headerAxisFiresForServe(r, g) {
		chMode = g.HeaderIntegrityResolvedAction()
	}
	// UA-TLS consistency (native): the nginx tier named a contradiction between
	// the User-Agent and the TLS fingerprint; the screen is the tier's own
	// (default CAPTCHA), never softening a deny, and it wins over the header
	// tier's as the attribution does.
	if cfg := h.cfg(); chMode != settings.RateChallengeDeny && uaTLSFiresForServe(r, *cfg) {
		chMode = cfg.Global.UATLSResolvedAction()
	}
	// A custom rule's own chain (native): the conf decided the request by
	// one of the operator's rules and names its action on the internal
	// rewrite to the challenge (X-Unmask-Rule-Action).  The rule was written
	// for exactly this request, so it replaces the chain the tiers above
	// chose; a hard deny is never softened (the conf answers 403 before a
	// deny ever reaches here anyway).
	if a := strings.TrimSpace(r.Header.Get("X-Unmask-Rule-Action")); a != "" && chMode != settings.RateChallengeDeny && settings.IsValidRateChallengeMode(a) && a != settings.RateChallengeDeny {
		chMode = a
	}
	// ?chm=: the chain-mode hint a wrapper's internal route may carry.  It
	// is taken only when nginx says the request came here from another URI
	// (X-Original-URI, set by the proxy and not the client's to forge, names
	// a page rather than this route).  On a direct hit of the public route
	// the query is the visitor's own: they could not get below what the
	// gate requires -- the backstop below holds that -- but they could pick
	// a lighter chain than the posture, and the record's ch_mode with it.
	if cm := strings.TrimSpace(r.URL.Query().Get("chm")); cm != "" && settings.IsValidRateChallengeMode(cm) && banProbedOrigPath(r, h.basePath()) != "" {
		chMode = cm
	}
	// Never serve a chain that cannot mint what the gate will demand.
	//
	// The requirement (a CAPTCHA-grade pass) and the screen (this chain) are
	// computed from the same settings but along different paths, and any input
	// one of them cannot see is a chance for them to disagree.  When they do,
	// the visitor is not merely inconvenienced: they solve the screen they were
	// given, present the credential it minted, are refused for holding the
	// wrong grade, and are handed the same screen again -- forever, with no way
	// out from the client side.  That is what a forward-auth node did to its
	// own operator's admin login, because the serve could not see the URI the
	// check had just matched a protected rule against.
	//
	// The resolver above is fixed, so this is the backstop: whatever route
	// picked the chain, if a CAPTCHA-grade pass is required then the chain has
	// to end in a CAPTCHA.  Escalating keeps the PoW leg, so it is never weaker
	// than what was picked, and it costs a request nothing when they agree.
	if chMode != settings.RateChallengeDeny && !chainEndsInCaptcha(chMode) {
		if requestNeedsCaptchaGrade(r.Header.Get("User-Agent"), protectedOrigURI(r, h.basePath()),
			siteFromRequest(r, h.snapshotSettings()), h.snapshotSettings()) {
			chMode = settings.RateChallengePoWThenCaptcha
		}
	}
	switch forceQuery {
	case "pow":
		chMode = settings.RateChallengePoWOnly
	case "captcha":
		chMode = settings.RateChallengeCaptchaOnly
	case "pow_then_captcha":
		chMode = settings.RateChallengePoWThenCaptcha
	}
	return chMode
}
