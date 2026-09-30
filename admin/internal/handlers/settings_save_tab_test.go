package handlers

import (
	"os"
	"regexp"
	"testing"
)

// Every settings form's save must come back to a tab the page renders: an
// unknown tab lands on the overview, away from what was just edited.  Saving
// the rate-limit tab (section=rate_limit) did exactly that.
func TestEverySettingsSaveReturnsToItsTab(t *testing.T) {
	src, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`save\?section=([a-z0-9_-]+)`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		seen[m[1]] = true
	}
	if len(seen) < 20 {
		t.Fatalf("found only %d save sections in settings.html -- the pattern no longer matches the forms", len(seen))
	}
	for section := range seen {
		if tab := tabForSection(section); !settingsTabs[tab] {
			t.Errorf("section %q redirects to tab %q, which the settings page does not render", section, tab)
		}
	}
	if got := tabForSection("rate_limit"); got != "rate-limit" {
		t.Errorf("rate_limit -> %q, want rate-limit", got)
	}
}
