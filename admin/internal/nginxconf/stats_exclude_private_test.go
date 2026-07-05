package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// renderHTTPInc renders and returns the http.inc (which carries the
// $unmask_stats_excluded geo).
func renderHTTPInc(t *testing.T, mutate func(*settings.Settings)) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	if mutate != nil {
		mutate(&s)
	}
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestStatsExcludePrivateNetworks: the preset appends the private CIDRs to the
// stats-exclude geo only when on, and always keeps the operator's custom
// entries.
func TestStatsExcludePrivateNetworks(t *testing.T) {
	off := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.StatsExcludeIPs = []string{"203.0.113.9"}
	})
	if strings.Contains(off, "10.0.0.0/8") {
		t.Errorf("private CIDRs must not render when the preset is off:\n%s", off)
	}
	if !strings.Contains(off, "203.0.113.9") {
		t.Errorf("custom stats-exclude entry missing")
	}

	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.StatsExcludeIPs = []string{"203.0.113.9"}
		s.Nginx.StatsExcludePrivateNetworks = true
	})
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "203.0.113.9"} {
		if !strings.Contains(on, want) {
			t.Errorf("stats-exclude geo missing %q when preset on:\n%s", want, on)
		}
	}
	// CGNAT is deliberately excluded (real ISP/mobile users behind it).
	if strings.Contains(on, "100.64.0.0/10") {
		t.Errorf("CGNAT must not be in the private-networks preset")
	}
}

// TestStatsExcludeListHelper unit-tests the append logic directly.
func TestStatsExcludeListHelper(t *testing.T) {
	var n settings.Nginx
	n.StatsExcludeIPs = []string{"1.2.3.4"}
	if got := statsExcludeList(n); len(got) != 1 {
		t.Errorf("off: expected only the custom entry, got %v", got)
	}
	n.StatsExcludePrivateNetworks = true
	got := statsExcludeList(n)
	if len(got) != 1+len(PrivateNetworkCIDRs) {
		t.Errorf("on: expected custom + %d private, got %d", len(PrivateNetworkCIDRs), len(got))
	}
	if got[0] != "1.2.3.4" {
		t.Errorf("custom entry should come first, got %v", got)
	}
	// must not mutate the stored list
	if len(n.StatsExcludeIPs) != 1 {
		t.Errorf("statsExcludeList must not mutate the config slice")
	}
}
