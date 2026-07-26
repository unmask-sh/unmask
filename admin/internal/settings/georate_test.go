package settings

import (
	"reflect"
	"testing"
)

// TestGeoConfigRateRules: only enabled effective-rate>0 rules are returned,
// with the action resolved against DefaultRuleAction; action-only rules and
// disabled rules are excluded.  The by-country twin of TestAsnConfigRateRules.
func TestGeoConfigRateRules(t *testing.T) {
	cfg := GeoConfig{
		Rules: []GeoRule{
			{Country: "CN", Action: GeoActionCaptchaOnly, RatePerMin: iptr(100), Enabled: true}, // rate rule
			{Country: "RU", Action: "", RatePerMin: iptr(50), Enabled: true},                    // rate rule, action inherits rule default
			{Country: "JP", Action: GeoActionDeny, Enabled: true},                               // action-only (rate 0) -> excluded
			{Country: "US", Action: GeoActionDeny, RatePerMin: iptr(10), Enabled: false},        // disabled -> excluded
		},
	}
	got := cfg.RateRules()
	want := []GeoRateRule{
		{Country: "CN", RatePerMin: 100, Action: GeoActionCaptchaOnly},
		{Country: "RU", RatePerMin: 50, Action: RateChallengePoWThenCaptcha}, // "" resolved to DefaultRuleAction
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RateRules() = %+v, want %+v", got, want)
	}
}

// TestGeoRateInherit: a nil rate inherits DefaultRatePerMin, an explicit *0
// opts out, an explicit *N stands -- mirroring the ASN inherit model.
func TestGeoRateInherit(t *testing.T) {
	zero := 0
	cfg := GeoConfig{
		DefaultRatePerMin: 100,
		Rules: []GeoRule{
			{Country: "CN", Action: GeoActionDeny, Enabled: true},                    // nil -> inherit 100
			{Country: "RU", Action: GeoActionDeny, RatePerMin: &zero, Enabled: true}, // explicit 0 -> no throttle
			{Country: "BR", Action: GeoActionDeny, RatePerMin: iptr(30), Enabled: true},
		},
	}
	if got := cfg.EffectiveRatePerMin(cfg.Rules[0].RatePerMin); got != 100 {
		t.Errorf("nil rate should inherit default 100, got %d", got)
	}
	if got := cfg.EffectiveRatePerMin(cfg.Rules[1].RatePerMin); got != 0 {
		t.Errorf("explicit *0 should be 0, got %d", got)
	}
	if got := cfg.EffectiveRatePerMin(cfg.Rules[2].RatePerMin); got != 30 {
		t.Errorf("explicit 30, got %d", got)
	}
	// RateRules picks up the inheriting rules (CN@100, BR@30) but not RU (*0).
	rr := cfg.RateRules()
	if len(rr) != 2 || rr[0].Country != "CN" || rr[0].RatePerMin != 100 || rr[1].Country != "BR" || rr[1].RatePerMin != 30 {
		t.Errorf("RateRules() = %+v, want CN@100 + BR@30", rr)
	}
}
