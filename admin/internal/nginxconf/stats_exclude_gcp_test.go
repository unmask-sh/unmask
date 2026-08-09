package nginxconf

import (
	"slices"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestStatsExcludeListFoldsGCPLBHC(t *testing.T) {
	base := settings.Nginx{StatsExcludeIPs: []string{"1.2.3.4"}}

	// both toggles off: only the operator's custom list.
	if got := statsExcludeList(base); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Fatalf("both off: got %v, want [1.2.3.4]", got)
	}

	// GCP on: HC ranges folded in, private networks NOT.
	n := base
	n.StatsExcludeGCPLBHC = true
	got := statsExcludeList(n)
	if !slices.Contains(got, "35.191.0.0/16") || !slices.Contains(got, "130.211.0.0/22") {
		t.Errorf("GCP on: HC ranges missing: %v", got)
	}
	if slices.Contains(got, "10.0.0.0/8") {
		t.Errorf("GCP on: a private-network CIDR leaked in: %v", got)
	}
	if !slices.Contains(got, "1.2.3.4") {
		t.Errorf("GCP on: the custom list must survive: %v", got)
	}

	// both on: custom + private + GCP, and the original slice is not mutated.
	n.StatsExcludePrivateNetworks = true
	got = statsExcludeList(n)
	for _, want := range []string{"1.2.3.4", "10.0.0.0/8", "35.191.0.0/16"} {
		if !slices.Contains(got, want) {
			t.Errorf("both on: missing %q in %v", want, got)
		}
	}
	if len(base.StatsExcludeIPs) != 1 {
		t.Errorf("statsExcludeList mutated the caller's slice: %v", base.StatsExcludeIPs)
	}
}
