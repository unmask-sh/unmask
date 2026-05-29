package communitybans

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// 66.249.64.0/19 is Googlebot's real range (= 66.249.64.0 - 66.249.95.255),
// used here so the test doubles as a sanity check on the accident we guard.
func TestBypassMatcher(t *testing.T) {
	var s settings.Settings
	s.Nginx.BypassIPs = []string{"66.249.64.0/19", "203.0.113.5", "", "  "}
	m := NewBypassMatcher(s)

	cases := []struct {
		ip   string
		want bool
	}{
		{"66.249.66.1", true},   // inside the /19
		{"66.249.95.255", true}, // top of the /19
		{"66.249.96.0", false},  // one past the /19
		{"203.0.113.5", true},   // exact single-IP row
		{"203.0.113.6", false},  // neighbour, not listed
		{"8.8.8.8", false},
		{"", false},          // ja4_only entry has no IP
		{"not-an-ip", false}, // garbage never matches
	}
	for _, c := range cases {
		if got := m.Match(c.ip); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestBypassMatcherDisabledRow(t *testing.T) {
	var s settings.Settings
	s.Nginx.BypassIPs = []string{"10.0.0.1", "10.0.0.2"}
	s.Nginx.BypassIPsDisabled = []bool{false, true} // operator turned the 2nd off
	m := NewBypassMatcher(s)
	if !m.Match("10.0.0.1") {
		t.Error("enabled row 10.0.0.1 should match")
	}
	if m.Match("10.0.0.2") {
		t.Error("disabled row 10.0.0.2 must NOT shield -- operator turned it off")
	}
}

func TestExcludeBypassedEntries(t *testing.T) {
	var s settings.Settings
	s.Nginx.BypassIPs = []string{"66.249.64.0/19"}
	m := NewBypassMatcher(s)

	entries := []FeedEntry{
		{Match: MatchIPOnly, IP: "66.249.66.1"},      // crawler -> drop
		{Match: MatchIPJA4, IP: "1.2.3.4", JA4: "x"}, // keep
		{Match: MatchJA4, JA4: "ja4only"},            // no IP -> keep (map-only)
		{Match: MatchIPOnly, IP: "66.249.80.9"},      // crawler -> drop
	}
	kept, skipped := excludeBypassedEntries(entries, m)
	if skipped != 2 {
		t.Fatalf("skipped = %d, want 2", skipped)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2", len(kept))
	}
	for _, e := range kept {
		if e.IP == "66.249.66.1" || e.IP == "66.249.80.9" {
			t.Errorf("crawler IP %s leaked into the enforced set", e.IP)
		}
	}
}

func TestExcludeBypassedEntriesNoConfig(t *testing.T) {
	// No bypass config -> matcher is a no-op and every entry is kept.
	m := NewBypassMatcher(settings.Settings{})
	entries := []FeedEntry{{Match: MatchIPOnly, IP: "1.2.3.4"}}
	kept, skipped := excludeBypassedEntries(entries, m)
	if skipped != 0 || len(kept) != 1 {
		t.Fatalf("no-bypass: kept=%d skipped=%d, want 1/0", len(kept), skipped)
	}
}

// Preset wiring: enabling a bypass-IP preset must expand into concrete ranges
// the matcher can use (= the auto-ban guard honours preset allowlists, not just
// hand-entered bypass_ips).
func TestEnforceableBypassCIDRsIncludesPresets(t *testing.T) {
	var s settings.Settings
	s.Nginx.BypassIPEnabledPresets = []string{"google-common"}
	if got := enforceableBypassCIDRs(s); len(got) == 0 {
		t.Fatal("google-common preset should expand to >= 1 CIDR")
	}
	m := NewBypassMatcher(s)
	if len(m.nets) == 0 && len(m.ips) == 0 {
		t.Fatal("matcher built from google-common is empty")
	}
}
