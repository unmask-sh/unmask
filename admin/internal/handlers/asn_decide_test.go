package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAsnDecideFor covers the ASN axis decision across its three targeting
// modes: an exact-ASN custom rule, an org-substring custom rule (covers a whole
// operator), and an enabled catalog provider.  Exact-ASN wins over an org match
// for the same visitor (more specific).
func TestAsnDecideFor(t *testing.T) {
	cfg := settings.AsnConfig{
		DefaultAction: settings.GeoActionSkip,
		Providers: []settings.AsnProviderSel{
			{ID: "digitalocean", Action: settings.GeoActionCaptchaOnly, Enabled: true},
			{ID: "google", Action: settings.GeoActionDeny, Enabled: false}, // disabled -> no opinion
		},
		Rules: []settings.AsnRule{
			{ASN: 16509, Action: settings.GeoActionDeny, Enabled: true},         // exact
			{Org: "OVH", Action: settings.GeoActionPoWOnly, Enabled: true},      // org substring
			{ASN: 99999, Action: settings.GeoActionCaptchaOnly, Enabled: false}, // disabled
		},
	}

	cases := []struct {
		name    string
		asn     uint
		org     string
		wantOK  bool
		wantSev axisSeverity
		wantR   string
	}{
		{"nothing resolved -> silent", 0, "", false, sevPass, ""},
		{"exact ASN deny", 16509, "Amazon.com", true, sevDeny, "asn:AS16509:deny"},
		{"org rule matches operator (reason names the visitor's AS)", 12876, "OVH SAS", true, sevPoWOnly, "asn:AS12876:pow_only"},
		{"provider match (DigitalOcean)", 14061, "DigitalOcean, LLC", true, sevCaptchaOnly, "asn:AS14061:captcha_only"},
		{"disabled provider -> silent", 15169, "Google LLC", false, sevPass, ""},
		{"disabled custom rule -> silent", 99999, "Somewhere", false, sevPass, ""},
		{"unmatched -> silent", 7922, "Comcast", false, sevPass, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := asnDecideFor(c.asn, c.org, cfg)
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

// TestAsnConfigResolveAction pins precedence: exact ASN beats org/provider,
// disabled entries are ignored, an unrelated org does not match.
func TestAsnConfigResolveAction(t *testing.T) {
	cfg := settings.AsnConfig{
		Providers: []settings.AsnProviderSel{{ID: "microsoft", Action: settings.GeoActionDeny, Enabled: true}},
		Rules: []settings.AsnRule{
			{ASN: 8075, Action: settings.GeoActionPoWOnly, Enabled: true}, // exact, an MS ASN
		},
	}
	// 8075 is Microsoft's org AND has an exact rule -> exact rule wins (pow_only).
	if act, ok := cfg.ResolveAction(8075, "Microsoft Corporation"); !ok || act != settings.GeoActionPoWOnly {
		t.Errorf("exact should win over provider: got %q ok=%v", act, ok)
	}
	// Another MS ASN with no exact rule -> provider deny (org match).
	if act, ok := cfg.ResolveAction(8068, "Microsoft Corporation"); !ok || act != settings.GeoActionDeny {
		t.Errorf("provider should match: got %q ok=%v", act, ok)
	}
	// Non-MS -> no match.
	if _, ok := cfg.ResolveAction(7922, "Comcast"); ok {
		t.Error("unrelated org must not match")
	}
}

// TestOrgMatchesAny pins case-insensitive substring matching.
func TestOrgMatchesAny(t *testing.T) {
	if !settings.OrgMatchesAny("Microsoft Corporation", []string{"microsoft"}) {
		t.Error("case-insensitive match failed")
	}
	if !settings.OrgMatchesAny("AKAMAI-LINODE-AP", []string{"Linode", "Akamai"}) {
		t.Error("multi-pattern match failed")
	}
	if settings.OrgMatchesAny("Comcast", []string{"Google"}) {
		t.Error("false positive")
	}
	if settings.OrgMatchesAny("", []string{"Google"}) {
		t.Error("empty org must not match")
	}
}
