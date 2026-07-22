package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// TestAICardRangeVerifiedRender renders the AI/crawler card template and pins
// the range-verified presentation the operator relies on, so neither piece can
// silently vanish again (the bottom legend once did):
//
//   - a range-verified crawler row carries a wordless 🛡 badge (class="ai-rv");
//   - a drill-down popover with at least one such crawler shows the one-line
//     legend at its foot (class="ai-rv-legend"), and a popover with none does not;
//   - the challenged-requests column reads "challenge" (renamed from "served").
func TestAICardRangeVerifiedRender(t *testing.T) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	render := func(detail map[string][]AICrawlerRow) string {
		data := map[string]any{
			"Lang":            i18n.LangEN,
			"AITraffic":       []AITrafficRow{{Category: "search-engine", Total: 100, Served: 90, Passed: 10}},
			"AITrafficServed": nil,
			"AITrafficDetail": detail,
		}
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, "ai_traffic_card", data); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}

	// "challenge" rename is on the always-present column header.
	base := render(nil)
	if !strings.Contains(base, "challenge") {
		t.Error(`served column header should read "challenge"`)
	}

	// A category with a range-verified crawler: badge on the row + legend at foot.
	withRV := render(map[string][]AICrawlerRow{
		"search-engine": {
			{Crawler: "Googlebot", Total: 34119, Served: 34112, Passed: 7, RangeVerified: true},
			{Crawler: "Yeti", Total: 427, Served: 50, Passed: 377, RangeVerified: false},
		},
	})
	if !strings.Contains(withRV, `class="ai-rv"`) || !strings.Contains(withRV, "🛡") {
		t.Error("range-verified crawler must render the 🛡 badge")
	}
	if !strings.Contains(withRV, `class="ai-rv-legend"`) {
		t.Error("a popover with a range-verified crawler must render the bottom legend")
	}

	// A category with no range-verified crawler: no badge, no legend.
	noRV := render(map[string][]AICrawlerRow{
		"search-engine": {
			{Crawler: "Yeti", Total: 427, Served: 50, Passed: 377, RangeVerified: false},
		},
	})
	if strings.Contains(noRV, `class="ai-rv"`) {
		t.Error("a crawler with no published range must not be badged")
	}
	if strings.Contains(noRV, `class="ai-rv-legend"`) {
		t.Error("a popover with no range-verified crawler must not show the legend")
	}
}
