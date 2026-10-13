package advisor

import "testing"

// TestHostingMatchSparesPrivateRelay: the hosting-network signals read the
// same catalog as the ASN tab, so the Akamai networks Apple's iCloud Private
// Relay leaves from are not a hosting network to the advisor either -- while
// Linode, named after Akamai in DB-IP, still is.
func TestHostingMatchSparesPrivateRelay(t *testing.T) {
	if hp := hostingMatch(36183, "Akamai Technologies, Inc."); hp != "" {
		t.Errorf("AS36183 (the relay) is a hosting network to the advisor: %q", hp)
	}
	if hp := hostingMatch(20940, "Akamai International B.V."); hp != "" {
		t.Errorf("AS20940 (the relay) is a hosting network to the advisor: %q", hp)
	}
	if hp := hostingMatch(63949, "Akamai Technologies, Inc."); hp == "" {
		t.Error("AS63949 (Linode) is no longer a hosting network to the advisor")
	}
	if hp := hostingMatch(0, ""); hp != "" {
		t.Errorf("an unknown network matched %q", hp)
	}
}
