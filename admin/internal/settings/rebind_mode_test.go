package settings

import "testing"

// RebindMode <-> (Disabled, ASNVeto) must round-trip for every operator-facing
// mode, and an unknown value must fall back to the safe default.
func TestRebindModeRoundTrip(t *testing.T) {
	cases := []struct {
		mode     string
		disabled bool
		asnVeto  string
	}{
		{"strict", true, ""},
		{"asn", false, "auto"},
		{"any", false, "off"},
	}
	for _, c := range cases {
		var rc RebindConfig
		rc.SetRebindMode(c.mode)
		if rc.Disabled != c.disabled || rc.ASNVeto != c.asnVeto {
			t.Errorf("SetRebindMode(%q): got Disabled=%v ASNVeto=%q, want %v/%q",
				c.mode, rc.Disabled, rc.ASNVeto, c.disabled, c.asnVeto)
		}
		if got := rc.RebindMode(); got != c.mode {
			t.Errorf("RebindMode after SetRebindMode(%q) = %q", c.mode, got)
		}
	}
	var rc RebindConfig
	rc.SetRebindMode("bogus")
	if rc.RebindMode() != "asn" {
		t.Errorf("unknown mode must fall back to asn, got %q", rc.RebindMode())
	}
}

// The roaming cap defaults to the ceiling and clamps to [1, 16].
func TestMaxEntriesResolvedClamp(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 16}, {-5, 16}, {1, 1}, {8, 8}, {16, 16}, {17, 16}, {999, 16},
	}
	for _, c := range cases {
		rc := RebindConfig{MaxEntries: c.in}
		if got := rc.MaxEntriesResolved(); got != c.want {
			t.Errorf("MaxEntriesResolved(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
