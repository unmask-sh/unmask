package settings

import (
	"reflect"
	"testing"
)

// TestAsnConfigRateRules: only enabled RatePerMin>0 custom rules are returned,
// with the action resolved against the default; action-only rules, disabled
// rules, and providers are excluded.
func TestAsnConfigRateRules(t *testing.T) {
	cfg := AsnConfig{
		DefaultAction: GeoActionPoWOnly,
		Providers:     []AsnProviderSel{{ID: "amazon", Action: GeoActionDeny, Enabled: true /* no rate on providers */}},
		Rules: []AsnRule{
			{ASN: 16509, Action: GeoActionCaptchaOnly, RatePerMin: iptr(100), Enabled: true}, // rate rule
			{Org: "OVH", Action: "", RatePerMin: iptr(50), Enabled: true},                    // rate rule, action inherits default
			{ASN: 14061, Action: GeoActionDeny, Enabled: true},                               // action-only (rate 0) -> excluded
			{ASN: 9999, Action: GeoActionDeny, RatePerMin: iptr(10), Enabled: false},         // disabled -> excluded
		},
	}
	got := cfg.RateRules()
	want := []AsnRateRule{
		{ASN: 16509, RatePerMin: 100, Action: GeoActionCaptchaOnly},       // AsnRateRule.RatePerMin is the resolved int
		{Org: "OVH", RatePerMin: 50, Action: RateChallengePoWThenCaptcha}, // "" resolved to DefaultRuleAction (NOT the unmatched default)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RateRules() = %+v, want %+v", got, want)
	}
}

// TestAsnRateInherit: a nil rate inherits DefaultRatePerMin (like "" action
// inherits DefaultAction); an explicit *0 opts out; providers inherit too.
func TestAsnRateInherit(t *testing.T) {
	zero := 0
	cfg := AsnConfig{
		DefaultAction:     GeoActionCaptchaOnly,
		DefaultRatePerMin: 100,                                                                       // the inherited default
		Providers:         []AsnProviderSel{{ID: "microsoft", Action: GeoActionDeny, Enabled: true}}, // nil rate -> inherit 100
		Rules: []AsnRule{
			{ASN: 16509, Action: GeoActionDeny, Enabled: true},                       // nil rate -> inherit 100
			{ASN: 14061, Action: GeoActionDeny, RatePerMin: &zero, Enabled: true},    // explicit 0 -> no throttle
			{ASN: 20473, Action: GeoActionDeny, RatePerMin: iptr(30), Enabled: true}, // explicit 30
		},
	}
	// ResolveRule: exact rule inherits the default.
	if _, rate, ok := cfg.ResolveRule(16509, "Amazon"); !ok || rate != 100 {
		t.Errorf("nil rate should inherit default 100: rate=%d ok=%v", rate, ok)
	}
	// Explicit 0 -> no throttle.
	if _, rate, _ := cfg.ResolveRule(14061, "DO"); rate != 0 {
		t.Errorf("explicit *0 should be 0, got %d", rate)
	}
	// Explicit 30.
	if _, rate, _ := cfg.ResolveRule(20473, "Vultr"); rate != 30 {
		t.Errorf("explicit 30, got %d", rate)
	}
	// Provider inherits the default -> appears in RateRules (as a rate zone).
	rr := cfg.RateRules()
	var msFound bool
	for _, r := range rr {
		if r.Org == "Microsoft" && r.RatePerMin == 100 {
			msFound = true
		}
	}
	if !msFound {
		t.Errorf("provider Microsoft should inherit default rate 100 into RateRules, got %+v", rr)
	}
}

// TestAsnConfigRateRulesEmpty: no rate rules -> empty.
func TestAsnConfigRateRulesEmpty(t *testing.T) {
	cfg := AsnConfig{Rules: []AsnRule{{ASN: 16509, Action: GeoActionDeny, Enabled: true}}}
	if got := cfg.RateRules(); len(got) != 0 {
		t.Errorf("RateRules() = %+v, want empty", got)
	}
}

func iptr(n int) *int { return &n }
