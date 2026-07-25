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
