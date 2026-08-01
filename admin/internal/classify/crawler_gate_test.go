package classify

import (
	"encoding/json"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// The literal pre-filter in LookupTag is an optimisation, and an optimisation
// that silently loses a crawler is worse than the cost it saves.  Every real
// UA the upstream list ships as an example must still classify -- run them all
// through the gated path and demand a tag for each.
func TestLiteralGateLosesNoCrawler(t *testing.T) {
	var entries []struct {
		Pattern   string   `json:"pattern"`
		Instances []string `json:"instances"`
	}
	if err := json.Unmarshal(assets.CrawlerUserAgentsJSON, &entries); err != nil {
		t.Fatal(err)
	}
	res := getCrawlerTagREs()

	checked, missed := 0, 0
	for _, e := range entries {
		for _, ua := range e.Instances {
			if ua == "" {
				continue
			}
			checked++
			// The ungated answer is the reference: does any tag regex match?
			want := ""
			for _, tag := range res.tagOrder {
				if re := res.tagRE[tag]; re != nil && re.MatchString(ua) {
					want = tag
					break
				}
			}
			if want == "" {
				continue // not classified either way; the gate is not at fault
			}
			if got := LookupTag(ua); got != want {
				missed++
				if missed <= 3 {
					t.Errorf("gate dropped a crawler: pattern %q ua %.70q -> %q, want %q",
						e.Pattern, ua, got, want)
				}
			}
		}
	}
	if checked < 500 {
		t.Fatalf("only %d instances checked; the list did not load", checked)
	}
	t.Logf("%d 件の実 UA を検証、取りこぼし %d 件 / literal %d 個 + 常時照合パターンあり=%v",
		checked, missed, len(res.litGate), res.ungatedRE != nil)
}
