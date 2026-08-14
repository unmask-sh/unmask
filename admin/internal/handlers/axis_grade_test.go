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
	if axisNeedsCaptchaGrade(4837, "China Unicom", "", false, false, cfg) {
		t.Error("an unmatched network was asked for a grade")
	}
}

// The live-incident shape: a ticked provider with nothing else filled in.  Its
// blank action inherits DefaultRuleAction (pow_then_captcha), and that chain
// ends in a CAPTCHA -- so a pow cookie must NOT satisfy it.  This is exactly
// the combination that passed 1,096 content pages in two hours.
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
