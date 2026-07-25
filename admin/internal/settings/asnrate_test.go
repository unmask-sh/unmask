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
			{ASN: 16509, Action: GeoActionCaptchaOnly, RatePerMin: 100, Enabled: true}, // rate rule
			{Org: "OVH", Action: "", RatePerMin: 50, Enabled: true},                    // rate rule, action inherits default
			{ASN: 14061, Action: GeoActionDeny, Enabled: true},                         // action-only (rate 0) -> excluded
			{ASN: 9999, Action: GeoActionDeny, RatePerMin: 10, Enabled: false},         // disabled -> excluded
		},
	}
	got := cfg.RateRules()
	want := []AsnRateRule{
		{ASN: 16509, RatePerMin: 100, Action: GeoActionCaptchaOnly},
		{Org: "OVH", RatePerMin: 50, Action: GeoActionPoWOnly}, // "" resolved to DefaultAction
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RateRules() = %+v, want %+v", got, want)
	}
}

// TestAsnConfigRateRulesEmpty: no rate rules -> empty.
func TestAsnConfigRateRulesEmpty(t *testing.T) {
	cfg := AsnConfig{Rules: []AsnRule{{ASN: 16509, Action: GeoActionDeny, Enabled: true}}}
	if got := cfg.RateRules(); len(got) != 0 {
		t.Errorf("RateRules() = %+v, want empty", got)
	}
}
