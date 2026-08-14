package handlers

import (
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// uaRequiresCaptchaGrade reports whether the operator's rules put this UA on a
// chain that ends in a CAPTCHA -- captcha_only, or pow_then_captcha, whose
// proof-of-work leg issues no cookie at all and hands off to the CAPTCHA.
//
// Why the question is worth asking of a client that already holds a pass:
// clearing a chain that ends in a CAPTCHA mints a CAPTCHA-grade cookie, so an
// ordinary visitor on such a rule is unaffected by anything gated on this.
// What is affected is a client holding a proof-of-work cookie it obtained
// some other way -- and "some other way" is a real, measured thing: a crawler
// read the challenge page, solved the 16-bit proof-of-work in its own code
// (never running our JavaScript, which is why the load counter stayed at 1 for
// a week), minted the cookie itself and served itself 137,051 requests a day
// through a rule that said CAPTCHA.
//
// The rule's own action wins over the list default, exactly as the render side
// resolves it.  An unlisted UA requires nothing: the operator has said nothing
// about it, and the Operating-mode buckets decide its posture.
func uaRequiresCaptchaGrade(ua string, cfg settings.Settings) bool {
	if ua == "" {
		return false
	}
	listed, category, action := lookupUAListed(ua, cfg.Nginx)
	if listed == "" || category != "challenge" {
		return false
	}
	act := strings.TrimSpace(action)
	if act == "" {
		// A listed row with no action of its own inherits the black-list
		// chain, through the resolver both wires decide with.
		act = cfg.UABlacklistChain()
	}
	return act == settings.RateChallengeCaptchaOnly || act == settings.RateChallengePoWThenCaptcha
}

// chainEndsInCaptcha reports whether a served chain finishes with a CAPTCHA --
// i.e. whether clearing it mints a CAPTCHA-grade pass.  The counterpart to
// gradeSatisfies: one says what a chain produces, the other what a gate
// accepts, and ServeChallenge refuses to hand out a chain whose product the
// gate would reject.
func chainEndsInCaptcha(chMode string) bool {
	return chMode == settings.RateChallengeCaptchaOnly ||
		chMode == settings.RateChallengePoWThenCaptcha
}

// requestNeedsCaptchaGrade reports whether THIS request must be backed by a
// CAPTCHA-grade cookie to pass, folding the two independent sources of a CAPTCHA
// requirement:
//
//   - the UA sits on a challenge-target chain that ends in a CAPTCHA
//     (uaRequiresCaptchaGrade), and/or
//   - the URI hits a protected path whose mode ends in a CAPTCHA
//     (captcha / pow_then_captcha).
//
// This is the forward-auth twin of native's $unmask_needs_captcha_grade map: a
// proof-of-work cookie must not satisfy a CAPTCHA gate on EITHER wire.  Before
// this, the forward-auth pass-cookie veto only consulted the UA source, so a
// PoW cookie sailed through a captcha-graded protected path (e.g. the admin
// login gate) — the hole this closes.
func requestNeedsCaptchaGrade(ua, uri, site string, cfg settings.Settings) bool {
	if uaRequiresCaptchaGrade(ua, cfg) {
		return true
	}
	return nginxconf.ModeEndsInCaptcha(protectedModeForOrig(cfg.Nginx, site, uri))
}

// gradeSatisfies reports whether a credential of grade `have` meets a CAPTCHA
// requirement.
//
// Only a genuine CAPTCHA solve does.  A re-bound credential is deliberately
// excluded even though it descends from one: the re-bind is what carries a
// solve onto addresses that never solved anything, and letting it satisfy the
// requirement would leave the exact hole this closes -- one CAPTCHA, then a
// fleet.  The lineage's own grade is checked separately on that path, so a
// roaming person who really did clear a CAPTCHA is still re-bound silently.
func gradeSatisfies(have string) bool {
	return have == "captcha"
}

// axisNeedsCaptchaGrade reports whether the geo or ASN axis puts this visitor
// on a chain that ends in a CAPTCHA -- the by-network sources of the grade
// requirement, joining the UA-chain / protected-path / community-feed sources.
//
// Why these belong in the gate: the pass-cookie veto runs before the axes, so
// without this an operator who answers a JS-executing botnet with an ASN or
// country rule saying captcha_only finds it stops only ADDRESSES THAT ARRIVE
// BARE.  Every address already holding a proof-of-work cookie -- minted under
// the global pow_only posture before the rule existed -- sails past the rule
// for the cookie's remaining lifetime.  Measured during the incident that
// motivated this: 1,096 content pages served in two hours through an ASN rule
// that said captcha_only, all to pow-cookie holders.
//
// Pure: lookups and exempt-path matching stay with the caller, so the
// requirement logic is testable without an mmdb on disk.
//
// Rate-mode entries (rate>0) impose nothing here: their action fires only on
// the overage, so under the cap the rule itself lets requests through -- a
// blanket grade demand would be stricter than the rule.  Deny ends nowhere, so
// it imposes nothing either (it never accepts any cookie; the deny path is
// enforced before cookies).
func axisNeedsCaptchaGrade(asn uint, org, country string, asnExempt, geoExempt bool, cfg settings.Settings) bool {
	if !asnExempt {
		if act, rate, ok := cfg.Nginx.Asn.ResolveRule(asn, org); ok && rate == 0 && chainEndsInCaptcha(act) {
			return true
		}
	}
	if !geoExempt {
		if d, rate, ok := geoDecideForCountry(country, cfg.Nginx.Geo); ok && rate == 0 && chainEndsInCaptcha(d.chMode) {
			return true
		}
	}
	return false
}

// axisNeedsCaptchaGradeFor is the handler-side wrapper: resolve the visitor's
// network identity from the mmdbs and the per-axis exempt paths, then ask the
// pure form.  Nil / unloaded readers contribute nothing, mirroring how
// asnDecide / geoDecide go inert without their databases.
func (h *Handler) axisNeedsCaptchaGradeFor(ip, uri string, matchers pathMatchers, cfg settings.Settings) bool {
	if h.IPGeo == nil {
		return false
	}
	var asn uint
	var org, country string
	if h.IPGeo.ASNLoaded() || h.IPGeo.Loaded() {
		info := h.IPGeo.LookupInfo(ip)
		if h.IPGeo.ASNLoaded() {
			asn, org = info.ASN, info.ASNOrg
		}
		if h.IPGeo.Loaded() {
			country = strings.ToUpper(strings.TrimSpace(info.Country))
		}
	}
	if asn == 0 && org == "" && country == "" {
		return false
	}
	return axisNeedsCaptchaGrade(asn, org, country,
		matchPath(uri, matchers.asnExempt), matchPath(uri, matchers.geoExempt), cfg)
}
