package settings

import "testing"

// TestProvidersMatchingQuery pins the brand/nickname bridge: product names the
// ASN mmdb does not carry in org strings must resolve to the right provider.
func TestProvidersMatchingQuery(t *testing.T) {
	cases := []struct {
		q      string
		wantID string // "" => expect no match
	}{
		{"azure", "microsoft"},     // alias -> Microsoft
		{"AZURE", "microsoft"},     // case-insensitive
		{"gcp", "google"},          // alias -> Google
		{"gce", "google"},          // alias -> Google
		{"aws", "amazon"},          // alias -> Amazon
		{"lightsail", "amazon"},    // alias -> Amazon
		{"aliyun", "alibaba"},      // alias -> Alibaba
		{"choopa", "vultr"},        // former name folded into Vultr
		{"microsoft", "microsoft"}, // by id/label
		{"kamatera", "kamatera"},   // renamed id resolves
	}
	for _, c := range cases {
		got := ProvidersMatchingQuery(c.q)
		if c.wantID == "" {
			if len(got) != 0 {
				t.Errorf("%q: want no match, got %d", c.q, len(got))
			}
			continue
		}
		found := false
		for _, hp := range got {
			if hp.ID == c.wantID {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want provider %q in matches, got %+v", c.q, c.wantID, got)
		}
	}
}

// TestProvidersMatchingQueryNoise: a numeric or unrelated query must not match a
// provider (numbers are AS numbers; org substrings are handled by the raw mmdb
// search, not this bridge).
func TestProvidersMatchingQueryNoise(t *testing.T) {
	for _, q := range []string{"16509", "comcast", "  "} {
		if got := ProvidersMatchingQuery(q); len(got) != 0 {
			t.Errorf("%q: want no provider match, got %+v", q, got)
		}
	}
}

// TestCatalogCleanup pins the preset-catalog hygiene decisions.
func TestCatalogCleanup(t *testing.T) {
	// Removed entries.
	for _, id := range []string{"cloudflare", "choopa", "digitalvirt"} {
		if HostingProviderByID(id) != nil {
			t.Errorf("provider %q should have been removed", id)
		}
	}
	// Kamatera keeps the sane id now.
	if HostingProviderByID("kamatera") == nil {
		t.Error("kamatera provider missing")
	}
	// Choopa folded into Vultr's org patterns (so legacy allocations still match).
	vultr := HostingProviderByID("vultr")
	if vultr == nil {
		t.Fatal("vultr missing")
		return // staticcheck does not read t.Fatal as terminating (SA5011)
	}
	hasChoopa := false
	for _, p := range vultr.OrgPatterns {
		if p == "Choopa" {
			hasChoopa = true
		}
	}
	if !hasChoopa {
		t.Errorf("vultr OrgPatterns should include Choopa, got %v", vultr.OrgPatterns)
	}
}

// privateRelayNetworks: the networks Apple's iCloud Private Relay leaves from,
// as the two ASN databases name them.  One address there is shared by every
// relay user it serves, so no provider may take them in: enabling a provider
// turns the whole network to its action at once.
var privateRelayNetworks = []struct {
	asn uint
	org string
}{
	{36183, "Akamai Technologies, Inc."}, // DB-IP
	{36183, "AKAMAI-AS"},                 // GeoLite2
	{20940, "Akamai International B.V."},
	{13335, "Cloudflare, Inc."},
	{13335, "CLOUDFLARENET"},
	{54113, "Fastly, Inc."},
	{54113, "FASTLY"},
}

func TestCatalogSparesPrivateRelay(t *testing.T) {
	for _, hp := range HostingProviders {
		for _, n := range privateRelayNetworks {
			if hp.Matches(n.asn, n.org) {
				t.Errorf("provider %s takes in AS%d %q, a network Apple's Private Relay leaves from", hp.ID, n.asn, n.org)
			}
		}
	}
}

// TestLinodeByNumber: DB-IP names Linode's network after Akamai, as it names
// the relay's, so the provider finds Linode by its AS number -- on every path
// that resolves a provider: the decision, the native walk's list, the rate
// zones.
func TestLinodeByNumber(t *testing.T) {
	hp := HostingProviderByID("linode")
	if hp == nil {
		t.Fatal("linode missing")
		return // staticcheck does not read t.Fatal as terminating (SA5011)
	}
	for _, n := range []struct {
		asn uint
		org string
	}{
		{63949, "Akamai Technologies, Inc."}, // DB-IP
		{63949, "Akamai Connected Cloud"},    // GeoLite2
		{0, "Akamai Connected Cloud"},        // the name alone
		{0, "Linode, LLC"},                   // an older database
	} {
		if !hp.Matches(n.asn, n.org) {
			t.Errorf("linode does not match AS%d %q", n.asn, n.org)
		}
	}

	a := AsnConfig{Providers: []AsnProviderSel{{ID: "linode", Action: GeoActionDeny, Enabled: true}}}
	if act, ok := a.ResolveAction(63949, "Akamai Technologies, Inc."); !ok || act != GeoActionDeny {
		t.Errorf("AS63949 resolves to (%q, %v), want (deny, true)", act, ok)
	}
	if act, ok := a.ResolveAction(36183, "Akamai Technologies, Inc."); ok {
		t.Errorf("AS36183 (the relay) resolves to %q under the linode provider", act)
	}
	if got := a.EnabledProviderASNs(); len(got) != 1 || got[0].ASN != 63949 || got[0].Action != GeoActionDeny {
		t.Errorf("EnabledProviderASNs = %+v, want AS63949 deny", got)
	}
	for _, p := range a.EnabledOrgPatterns() {
		if p.Pattern == "Akamai" {
			t.Error("the bare Akamai pattern is still in the walk")
		}
	}

	// A throttled provider renders as a rate zone instead, its number with it.
	rate := 30
	a.Providers[0].RatePerMin = &rate
	if got := a.EnabledProviderASNs(); len(got) != 0 {
		t.Errorf("a throttled provider stays out of the action list, got %+v", got)
	}
	found := false
	for _, r := range a.RateRules() {
		if r.ASN == 63949 && r.RatePerMin == rate && r.Action == GeoActionDeny {
			found = true
		}
	}
	if !found {
		t.Errorf("RateRules = %+v, want AS63949 at %d/min", a.RateRules(), rate)
	}
}
