package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// lookupASNRuleAction answers the only question the ASN ranking has to answer
// before an operator acts on a row: is this network already covered?  Getting
// it wrong in either direction is costly -- a false "covered" hides a network
// that is still being let through, and a false "uncovered" invites a second,
// conflicting rule for a network already handled.
func TestLookupASNRuleAction(t *testing.T) {
	rate := func(n int) *int { return &n }
	cfg := settings.AsnConfig{
		DefaultRuleAction: "pow_then_captcha",
		Rules: []settings.AsnRule{
			{ASN: 16509, Action: "deny", Enabled: true},
			{ASN: 24940, Action: "", Enabled: true},                              // blank -> inherits the rule default
			{Org: "Datacamp", Action: "captcha_only", Enabled: true},             // org substring
			{ASN: 9009, Action: "pow_only", RatePerMin: rate(30), Enabled: true}, // rate mode
			{ASN: 64500, Action: "deny", Enabled: false},                         // disabled -> not covered
		},
	}

	for _, tc := range []struct {
		name string
		asn  uint
		org  string
		want string
	}{
		{"exact ASN", 16509, "Amazon.com, Inc.", "deny"},
		{"blank action inherits the rule default", 24940, "Hurricane Electric", "pow_then_captcha"},
		{"org substring, case-insensitive", 212238, "DATACAMP LIMITED", "captcha_only"},
		{"rate-mode rule still counts as covered", 9009, "M247 Europe SRL", "pow_only"},
		{"disabled rule does not cover", 64500, "Example Net", ""},
		{"unknown network", 398781, "OCULUS NETWORKS INC", ""},
		{"unresolved ASN with no org matches nothing", 0, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lookupASNRuleAction(tc.asn, tc.org, cfg); got != tc.want {
				t.Errorf("AS%d %q: want %q, got %q", tc.asn, tc.org, tc.want, got)
			}
		})
	}
}

// An ASN 0 row (mmdb had no answer) must not be matched by an org rule just
// because the org string happens to be empty on both sides -- an empty pattern
// would otherwise substring-match everything.
func TestLookupASNRuleActionIgnoresEmptyOrgPattern(t *testing.T) {
	cfg := settings.AsnConfig{
		DefaultRuleAction: "deny",
		Rules:             []settings.AsnRule{{Org: "   ", Action: "deny", Enabled: true}},
	}
	if got := lookupASNRuleAction(0, "", cfg); got != "" {
		t.Fatalf("a blank org pattern must match nothing, got %q", got)
	}
	if got := lookupASNRuleAction(398781, "OCULUS NETWORKS INC", cfg); got != "" {
		t.Fatalf("a blank org pattern must match nothing, got %q", got)
	}
}
