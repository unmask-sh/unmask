package ipgeo

import "testing"

// TestASNRateCIDRsGuards pins the no-op guards (no mmdb needed): an empty path,
// no targets, or targets that name neither an AS number nor an org all return
// "" so a rate config with nothing to render emits an empty geo block.  The walk
// itself is exercised against a real ASN mmdb in development.
func TestASNRateCIDRsGuards(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		targets []ASNTarget
	}{
		{"empty path", "", []ASNTarget{{ASN: 13335}}},
		{"no targets", "/nonexistent.mmdb", nil},
		{"targets with no ASN/org", "/nonexistent.mmdb", []ASNTarget{{Value: "x"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ASNRateCIDRs(c.path, c.targets)
			if err != nil || got != "" {
				t.Errorf("ASNRateCIDRs = (%q, %v), want (\"\", nil)", got, err)
			}
		})
	}
}

// TestASNMatcherOrder: an exact AS number outranks everything; the rest --
// org substrings and the AS numbers a catalog provider names (InOrder) --
// match in the caller's order, so a custom org rule placed ahead of a
// provider keeps a network the two share, as AsnConfig.ResolveRule does.
func TestASNMatcherOrder(t *testing.T) {
	m := newASNMatcher([]ASNTarget{
		{ASN: 16509, Value: "AS16509"},
		{OrgPattern: "Akamai Technologies", Value: "org:akamai technologies"},
		{ASN: 63949, InOrder: true, Value: "AS63949"},
		{OrgPattern: "Akamai Connected Cloud", Value: "org:akamai connected cloud"},
	})
	for _, c := range []struct {
		asn       uint
		org, want string
	}{
		{16509, "Amazon.com, Inc.", "AS16509"},
		{63949, "Akamai Technologies, Inc.", "org:akamai technologies"}, // the custom org rule ranks first
		{63949, "Akamai Connected Cloud", "AS63949"},                    // the number, ahead of the later pattern
		{0, "AKAMAI CONNECTED CLOUD", "org:akamai connected cloud"},     // case-insensitive
		{36183, "AKAMAI-AS", ""},
		{13335, "", ""},
	} {
		if got := m.value(c.asn, c.org); got != c.want {
			t.Errorf("AS%d %q -> %q, want %q", c.asn, c.org, got, c.want)
		}
	}
	if !newASNMatcher([]ASNTarget{{Value: "x"}}).empty() {
		t.Error("a target naming neither an AS number nor an org is no target")
	}
}
