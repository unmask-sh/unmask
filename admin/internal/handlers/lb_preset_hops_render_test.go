package handlers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// A trusted-LB preset can carry two lists (nginxconf.LBIPRange): the ranges
// its proxies connect from, and the load balancer's own addresses, which
// real_ip only reads past in X-Forwarded-For.  The network tab lists both
// under the preset, the second under a line that says what it is: an operator
// who opens the list has to be able to tell which ranges are believed about a
// visitor's JA4 and which are not.  The count on the row stays the proxies'.
func TestNetworkTabListsTheReadPastRangesApart(t *testing.T) {
	h := newTestHandler(t)
	body := renderSettingsTab(t, h, "network")

	withHops := 0
	for _, p := range nginxconf.LBIPRanges {
		if len(p.CIDRs) == 0 || len(p.XFFHops) == 0 {
			continue
		}
		withHops++
		// The preset's own block of the page: from its checkbox to the next one.
		at := strings.Index(body, `name="trusted_lb_preset" value="`+p.ID+`"`)
		if at < 0 {
			t.Fatalf("preset %s is not on the network tab", p.ID)
		}
		block := body[at:]
		if next := strings.Index(block[1:], `name="trusted_lb_preset" value="`); next >= 0 {
			block = block[:next+1]
		}
		if want := fmt.Sprintf("<summary>%d CIDRs</summary>", len(p.CIDRs)); !strings.Contains(block, want) {
			t.Errorf("preset %s: the row does not count its proxies' ranges (%q)", p.ID, want)
		}
		label := fmt.Sprintf("(%d 帯)", len(p.XFFHops))
		li := strings.Index(block, label)
		if li < 0 {
			t.Fatalf("preset %s: no line naming its %d read-past ranges", p.ID, len(p.XFFHops))
		}
		// Every proxy range before the line, every read-past range after it.
		for _, c := range p.CIDRs {
			if i := strings.Index(block, "<div>"+c+"</div>"); i < 0 || i > li {
				t.Errorf("preset %s: proxy range %s is not listed above the line", p.ID, c)
			}
		}
		for _, c := range p.XFFHops {
			if i := strings.Index(block, "<div>"+c+"</div>"); i < li {
				t.Errorf("preset %s: read-past range %s is not listed under the line", p.ID, c)
			}
		}
	}
	if withHops == 0 {
		t.Fatal("no preset carries read-past ranges: the Google Cloud one should")
	}
	// A preset without such addresses gets no such line.
	if got := strings.Count(body, "中継元としては信頼しません"); got != withHops {
		t.Errorf("the line appears %d times, for %d presets that have such ranges", got, withHops)
	}
}
