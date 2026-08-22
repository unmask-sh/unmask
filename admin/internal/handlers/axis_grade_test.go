package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The forward-auth twin of the native $unmask_geo_captcha / $unmask_asn_captcha
// wiring: a network rule that ends in a CAPTCHA must make a proof-of-work
// cookie insufficient.  Pure-function tests -- the mmdb lookups and exempt-path
// matching stay with the caller.

func asnCfg(rules []settings.AsnRule, provs []settings.AsnProviderSel) settings.Settings {
	var s settings.Settings
	s.Nginx.Asn.Rules = rules
	s.Nginx.Asn.Providers = provs
	return s
}

func TestAxisGrade_ASNCaptchaRuleRequires(t *testing.T) {
	cfg := asnCfg([]settings.AsnRule{{ASN: 132203, Action: settings.GeoActionCaptchaOnly, Enabled: true}}, nil)
	if !axisNeedsCaptchaGrade(132203, "Tencent", "", false, false, cfg) {
		t.Error("a captcha_only ASN rule imposed no grade requirement")
	}
	if axisNeedsCaptchaGrade(64500, "Example Telecom", "", false, false, cfg) {
		t.Error("an unmatched network was asked for a grade")
	}
}

// The live-incident shape: a ticked provider with nothing else filled in.  Its
// blank action inherits DefaultRuleAction (pow_then_captcha), and that chain
// ends in a CAPTCHA -- so a pow cookie must NOT satisfy it.  This is exactly
// the combination that let a proxy herd ride content pages in bulk.
func TestAxisGrade_ProviderInheritedChainRequires(t *testing.T) {
	cfg := asnCfg(nil, []settings.AsnProviderSel{{ID: "tencent", Enabled: true}})
	if !axisNeedsCaptchaGrade(132203, "Tencent Building, Kejizhongyi Avenue", "", false, false, cfg) {
		t.Error("an enabled provider on the inherited pow_then_captcha chain imposed no grade requirement")
	}
}

func TestAxisGrade_ExemptPathSkipsItsAxisOnly(t *testing.T) {
	cfg := asnCfg([]settings.AsnRule{{ASN: 132203, Action: settings.GeoActionCaptchaOnly, Enabled: true}}, nil)
	cfg.Nginx.Geo.Rules = []settings.GeoRule{{Country: "CN", Action: settings.GeoActionCaptchaOnly, Enabled: true}}

	if axisNeedsCaptchaGrade(132203, "Tencent", "", true, false, cfg) {
		t.Error("an asn-exempt path still demanded the grade for the ASN rule")
	}
	// Same visitor, geo also matched: the asn exemption must not silence geo.
	if !axisNeedsCaptchaGrade(132203, "Tencent", "CN", true, false, cfg) {
		t.Error("the asn exemption silenced the geo source too")
	}
	if axisNeedsCaptchaGrade(0, "", "CN", false, true, cfg) {
		t.Error("a geo-exempt path still demanded the grade for the geo rule")
	}
}

// A rate-mode entry acts only on the overage; under the cap the rule itself
// passes requests, so a blanket grade demand would be stricter than the rule.
func TestAxisGrade_RateModeImposesNothing(t *testing.T) {
	rate := 60
	cfg := asnCfg([]settings.AsnRule{{ASN: 132203, Action: settings.GeoActionCaptchaOnly, RatePerMin: &rate, Enabled: true}}, nil)
	if axisNeedsCaptchaGrade(132203, "Tencent", "", false, false, cfg) {
		t.Error("a rate-mode rule imposed a blanket grade requirement")
	}
}

// Deny never accepts any cookie (it is enforced before cookies), and pow_only
// mints exactly the cookie it accepts -- neither demands the CAPTCHA grade.
func TestAxisGrade_NonCaptchaActionsImposeNothing(t *testing.T) {
	for _, act := range []string{settings.GeoActionPoWOnly, settings.GeoActionDeny, settings.GeoActionSkip} {
		cfg := asnCfg([]settings.AsnRule{{ASN: 1, Action: act, Enabled: true}}, nil)
		if axisNeedsCaptchaGrade(1, "x", "", false, false, cfg) {
			t.Errorf("action %q imposed a grade requirement", act)
		}
	}
}

func TestAxisGrade_GeoRuleRequires(t *testing.T) {
	var cfg settings.Settings
	cfg.Nginx.Geo.Rules = []settings.GeoRule{{Country: "CN", Action: settings.GeoActionPoWThenCaptcha, Enabled: true}}
	if !axisNeedsCaptchaGrade(0, "", "CN", false, false, cfg) {
		t.Error("a pow_then_captcha geo rule imposed no grade requirement")
	}
	if axisNeedsCaptchaGrade(0, "", "JP", false, false, cfg) {
		t.Error("an unmatched country was asked for a grade")
	}
}

// The wrapper goes inert without a reader, exactly like asnDecide / geoDecide
// -- a forward-auth install with no mmdb keeps its pre-fix behaviour.
func TestAxisGrade_NoReaderMeansNoRequirement(t *testing.T) {
	h := &Handler{}
	cfg := asnCfg([]settings.AsnRule{{ASN: 1, Action: settings.GeoActionCaptchaOnly, Enabled: true}}, nil)
	if h.axisNeedsCaptchaGradeFor("1.2.3.4", "/x", pathMatchers{}, cfg) {
		t.Error("a nil IPGeo reader still produced a grade requirement")
	}
}

// The by-fingerprint sibling: a JA4 verdict row whose effective chain ends in
// a CAPTCHA must make a proof-of-work cookie insufficient for that
// fingerprint.  Driven through matchJA4 (the per-request resolution the veto
// reuses) so the test exercises the same verdict/action pair the wire sees.
func TestAxisGrade_JA4CaptchaRowRequires(t *testing.T) {
	const herd = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	var s settings.Settings
	s.Nginx.JA4Verdicts.Extra = []settings.JA4VerdictExtraRule{{
		ID: 100, Pattern: "^" + herd + "$", Verdict: "bot_residential_herd", Action: "bot",
	}}
	s.Nginx.JA4Verdicts.ExtraAction = []string{settings.RateChallengeCaptchaOnly}

	verdict, action := matchJA4(herd, s.Nginx)
	if !ja4NeedsCaptchaGrade(verdict, action, s) {
		t.Error("a captcha_only JA4 row imposed no grade requirement")
	}
	verdict, action = matchJA4("t13d1516h2_8daaf6152771_806a8c22fdea", s.Nginx)
	if ja4NeedsCaptchaGrade(verdict, action, s) {
		t.Error("an unmatched fingerprint was asked for a grade")
	}
}

// A bot row with no configured chain anywhere inherits the operating default
// (pow_then_captcha on a fresh install) -- the same chain ja4Decide answers
// checks with and the serve hands out.  The grade requirement has to follow
// it, or a proof-of-work cookie obtained under some other fingerprint becomes
// the one credential that sails past a bot verdict.
func TestAxisGrade_JA4UnconfiguredChainInheritsOperatingDefault(t *testing.T) {
	const herd = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	var s settings.Settings
	s.Nginx.JA4Verdicts.Extra = []settings.JA4VerdictExtraRule{{
		ID: 100, Pattern: "^" + herd + "$", Verdict: "bot_residential_herd", Action: "bot",
	}}
	verdict, action := matchJA4(herd, s.Nginx)
	if !ja4NeedsCaptchaGrade(verdict, action, s) {
		t.Error("the inherited pow_then_captcha default imposed no grade requirement")
	}

	// An operating default of pow_only flows through the same inheritance:
	// serve and gate then agree on a chain that mints exactly the cookie it
	// accepts, so no requirement -- and no gate/serve challenge loop.
	s.RateLimit.Default.ChallengeMode = settings.RateChallengePoWOnly
	verdict, action = matchJA4(herd, s.Nginx)
	if ja4NeedsCaptchaGrade(verdict, action, s) {
		t.Error("a pow_only operating default still imposed a grade requirement")
	}
}

// The JA4 tab's own default chain covers rows without a per-row action --
// the live fleet shape (default_action: pow_then_captcha, rows inherit).
// A suspect row stays observation-only regardless.
func TestAxisGrade_JA4DefaultChainAndSuspect(t *testing.T) {
	const hunt = "t13d450900_d524c25c267f_9da38b6fd1bc"
	var s settings.Settings
	s.Nginx.JA4Verdicts.DefaultAction = settings.RateChallengePoWThenCaptcha
	s.Nginx.JA4Verdicts.Extra = []settings.JA4VerdictExtraRule{{
		ID: 100, Pattern: hunt, Verdict: "hunt_row", Action: "bot",
	}}
	verdict, action := matchJA4(hunt, s.Nginx)
	if !ja4NeedsCaptchaGrade(verdict, action, s) {
		t.Error("the tab default pow_then_captcha chain imposed no grade requirement")
	}

	s.Nginx.JA4Verdicts.Extra[0].Action = "suspect"
	verdict, action = matchJA4(hunt, s.Nginx)
	if ja4NeedsCaptchaGrade(verdict, action, s) {
		t.Error("a suspect (observation-only) row imposed a grade requirement")
	}
}

// An explicit pow_only row is the per-row opt-out even under a captcha-ending
// tab default.  A disabled row matches nothing at all.
func TestAxisGrade_JA4RowOptOutAndDisabled(t *testing.T) {
	const herd = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	var s settings.Settings
	s.Nginx.JA4Verdicts.DefaultAction = settings.RateChallengeCaptchaOnly
	s.Nginx.JA4Verdicts.Extra = []settings.JA4VerdictExtraRule{{
		ID: 100, Pattern: "^" + herd + "$", Verdict: "bot_residential_herd", Action: "bot",
	}}
	s.Nginx.JA4Verdicts.ExtraAction = []string{settings.RateChallengePoWOnly}
	verdict, action := matchJA4(herd, s.Nginx)
	if ja4NeedsCaptchaGrade(verdict, action, s) {
		t.Error("an explicit pow_only row still imposed a grade requirement")
	}

	s.Nginx.JA4Verdicts.ExtraAction = []string{settings.RateChallengeCaptchaOnly}
	s.Nginx.JA4Verdicts.ExtraDisabled = []bool{true}
	verdict, action = matchJA4(herd, s.Nginx)
	if ja4NeedsCaptchaGrade(verdict, action, s) {
		t.Error("a disabled row still imposed a grade requirement")
	}
}
