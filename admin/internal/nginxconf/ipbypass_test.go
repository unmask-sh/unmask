package nginxconf

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestIPBypassMatcher(t *testing.T) {
	var n settings.Nginx
	n.BypassIPs = []string{"66.249.64.0/19", "203.0.113.5", "", "  "}
	m := NewIPBypassMatcher(n)

	cases := []struct {
		ip   string
		want bool
	}{
		{"66.249.66.1", true},   // inside the /19 (Googlebot)
		{"66.249.95.255", true}, // top of the /19
		{"66.249.96.0", false},  // one past the /19
		{"203.0.113.5", true},   // exact single-IP row
		{"203.0.113.6", false},  // neighbour, not listed
		{"8.8.8.8", false},
		{"", false},          // empty never matches
		{"not-an-ip", false}, // garbage never matches
	}
	for _, c := range cases {
		if got := m.Match(c.ip); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestIPBypassMatcherDisabledRow(t *testing.T) {
	var n settings.Nginx
	n.BypassIPs = []string{"10.0.0.1", "10.0.0.2"}
	n.BypassIPsDisabled = []bool{false, true} // operator turned the 2nd off
	m := NewIPBypassMatcher(n)
	if !m.Match("10.0.0.1") {
		t.Error("enabled row 10.0.0.1 should match")
	}
	if m.Match("10.0.0.2") {
		t.Error("disabled row 10.0.0.2 must NOT shield -- operator turned it off")
	}
}

func TestIPBypassMatcherEmpty(t *testing.T) {
	if !NewIPBypassMatcher(settings.Nginx{}).Empty() {
		t.Error("no config -> Empty() should be true")
	}
	var n settings.Nginx
	n.BypassIPs = []string{"1.2.3.4"}
	if NewIPBypassMatcher(n).Empty() {
		t.Error("one row -> Empty() should be false")
	}
}

// Preset wiring: enabling a bypass-IP preset must expand into concrete ranges
// (= the matcher honours preset allowlists, not just hand-entered bypass_ips).
func TestBypassIPCIDRsIncludesPresets(t *testing.T) {
	var n settings.Nginx
	n.BypassIPEnabledPresets = []string{"google-common"}
	if got := BypassIPCIDRs(n); len(got) == 0 {
		t.Fatal("google-common preset should expand to >= 1 CIDR")
	}
	if NewIPBypassMatcher(n).Empty() {
		t.Fatal("matcher built from google-common is empty")
	}
}
