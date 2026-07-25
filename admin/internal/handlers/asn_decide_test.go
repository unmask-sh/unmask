package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAsnDecideForASN mirrors TestGeoDecideForCountry: per-ASN policy
// resolution covering default fallback, rule override, the "skip" no-op, the
// "deny" hard 403, ASN 0 (mmdb miss / private IP), and a disabled rule.
func TestAsnDecideForASN(t *testing.T) {
	rules := []settings.AsnRule{
		{ASN: 16509, Action: settings.GeoActionDeny, Enabled: true},         // Amazon -> deny
		{ASN: 14061, Action: settings.GeoActionCaptchaOnly, Enabled: true},  // DigitalOcean -> captcha
		{ASN: 396982, Action: settings.GeoActionSkip, Enabled: true},        // GCP -> explicit skip
		{ASN: 13335, Action: settings.RateChallengePoWOnly, Enabled: false}, // disabled -> no opinion
		{ASN: 20473, Action: "", Enabled: true},                             // inherit default
	}
	skipDefault := settings.AsnConfig{DefaultAction: settings.GeoActionSkip, Rules: rules}
	denyDefault := settings.AsnConfig{DefaultAction: settings.GeoActionDeny, Rules: rules}

	cases := []struct {
		name    string
		asn     uint
		cfg     settings.AsnConfig
		wantOK  bool
		wantSev axisSeverity
		wantR   string
	}{
		{"asn 0 -> silent", 0, skipDefault, false, sevPass, ""},
		{"Amazon deny", 16509, skipDefault, true, sevDeny, "asn:AS16509:deny"},
		{"DigitalOcean captcha", 14061, skipDefault, true, sevCaptchaOnly, "asn:AS14061:captcha_only"},
		{"GCP explicit skip -> silent", 396982, skipDefault, false, sevPass, ""},
		{"disabled rule -> default skip -> silent", 13335, skipDefault, false, sevPass, ""},
		{"inherit default skip -> silent", 20473, skipDefault, false, sevPass, ""},
		{"inherit default deny -> deny", 20473, denyDefault, true, sevDeny, "asn:AS20473:deny"},
		{"unlisted ASN, default skip -> silent", 7922, skipDefault, false, sevPass, ""},
		{"unlisted ASN, default deny -> deny", 7922, denyDefault, true, sevDeny, "asn:AS7922:deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := asnDecideForASN(c.asn, c.cfg)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (decision=%+v)", ok, c.wantOK, d)
			}
			if !ok {
				return
			}
			if d.sev != c.wantSev || d.reason != c.wantR {
				t.Errorf("decision=(sev=%d, reason=%q), want (sev=%d, reason=%q)",
					d.sev, d.reason, c.wantSev, c.wantR)
			}
		})
	}
}

// TestAsnConfigHelpers pins ResolvedDefaultAction and LookupRule (enabled/
// disabled/zero).
func TestAsnConfigHelpers(t *testing.T) {
	if got := (settings.AsnConfig{}).ResolvedDefaultAction(); got != settings.GeoActionSkip {
		t.Errorf("empty default -> %q, want skip", got)
	}
	cfg := settings.AsnConfig{Rules: []settings.AsnRule{
		{ASN: 16509, Action: settings.GeoActionDeny, Enabled: true},
		{ASN: 14061, Action: settings.GeoActionDeny, Enabled: false},
	}}
	if r := cfg.LookupRule(16509); r == nil || r.ASN != 16509 {
		t.Error("enabled rule not found")
	}
	if r := cfg.LookupRule(14061); r != nil {
		t.Error("disabled rule must not resolve")
	}
	if r := cfg.LookupRule(0); r != nil {
		t.Error("ASN 0 must not resolve")
	}
}
