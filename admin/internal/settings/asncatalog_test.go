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
