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

// Forward-auth parity: stats_exclude_ips are folded into the native
// geo $is_bypass_ip (they skip the challenge), so the IPBypassMatcher the
// forward-auth authcheck consults must match them too -- otherwise a monitoring
// probe from a stats-exclude IP is challenged on a forward-auth host (tool1-sg)
// but passes on a native one (tool1-jp/us/gb), a permanent xymon false-positive.
func TestIPBypassMatcherIncludesStatsExclude(t *testing.T) {
	var n settings.Nginx // no explicit bypass_ips rows: the IPs come only from stats_exclude
	n.StatsExcludeIPs = []string{"10.8.100.1", "153.121.77.40"}
	m := NewIPBypassMatcher(n)
	for _, ip := range []string{"10.8.100.1", "153.121.77.40"} {
		if !m.Match(ip) {
			t.Errorf("stats-exclude IP %s must bypass the forward-auth challenge (native $is_bypass_ip folds it in)", ip)
		}
	}
	if m.Match("8.8.8.8") {
		t.Error("an IP in neither bypass_ips nor stats_exclude must not match")
	}

	// The private-networks stats-exclude preset bypasses in native (folded into
	// $is_bypass_ip when on); forward-auth must agree.
	var p settings.Nginx
	p.StatsExcludePrivateNetworks = true
	mp := NewIPBypassMatcher(p)
	if !mp.Match("10.1.2.3") || !mp.Match("192.168.5.5") {
		t.Error("private-networks stats-exclude preset must bypass RFC1918 in forward-auth too")
	}
	if mp.Match("8.8.8.8") {
		t.Error("a public IP must not match the private-networks preset")
	}
}
