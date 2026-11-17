package settings

import "testing"

// TestWalkEntriesKeepThrottledEntriesAsSkip: the native walk lists a
// throttled rule or provider where it ranks, mapped to skip, and every other
// entry with its resolved action, in the order of the three lists the walk
// used to read (EnabledASNRules, EnabledOrgPatterns, EnabledProviderASNs).
// Those lists leave a throttled entry out, and its network fell to the
// default for networks no rule names on every request under the cap.
func TestWalkEntriesKeepThrottledEntriesAsSkip(t *testing.T) {
	rate := 30
	a := AsnConfig{
		DefaultAction: RateChallengeCaptchaOnly,
		Rules: []AsnRule{
			{ASN: 64500, Action: RateChallengeCaptchaOnly, Enabled: true},
			{ASN: 64501, Action: RateChallengeCaptchaOnly, RatePerMin: &rate, Enabled: true},
			{Org: "Example Cloud", Action: GeoActionDeny, RatePerMin: &rate, Enabled: true},
			{ASN: 64502, Enabled: true}, // blank: the registered-row default
			{ASN: 64503, Action: GeoActionDeny},
		},
		Providers: []AsnProviderSel{{ID: "linode", Action: GeoActionDeny, RatePerMin: &rate, Enabled: true}},
	}
	got := a.WalkEntries()
	hp := HostingProviderByID("linode")
	if hp == nil {
		t.Fatal("precondition: the linode provider is in the catalog")
	}
	want := []AsnWalkEntry{
		{ASN: 64500, Action: RateChallengeCaptchaOnly},
		{ASN: 64501, Action: GeoActionSkip},
		{ASN: 64502, Action: a.ResolvedDefaultRuleAction()},
		{OrgPattern: "Example Cloud", Action: GeoActionSkip},
	}
	for _, pat := range hp.OrgPatterns {
		want = append(want, AsnWalkEntry{OrgPattern: pat, Action: GeoActionSkip})
	}
	for _, n := range hp.ASNs {
		want = append(want, AsnWalkEntry{ASN: n, Provider: true, Action: GeoActionSkip})
	}
	if len(got) != len(want) {
		t.Fatalf("WalkEntries = %+v\nwant %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// The three lists themselves are untouched: the hunt page reads them for
	// a rule's overage action, which a throttled rule reports from RateRules.
	for _, r := range a.EnabledASNRules() {
		if r.ASN == 64501 {
			t.Error("EnabledASNRules now lists the throttled rule")
		}
	}
}
