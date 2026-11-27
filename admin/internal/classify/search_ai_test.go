package classify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// searchAIReference is IsBot's search_ai branch as it stood before the
// pre-filter: the joined pattern over the whole User-Agent, then the
// crawlers the operator took out of the rescue.
func searchAIReference(ua string) bool {
	res := getCategoryREs()
	if ua == "" || !res.searchAI.MatchString(ua) {
		return false
	}
	upstreamUnrescuedMu.RLock()
	unrescued := upstreamUnrescuedRE
	upstreamUnrescuedMu.RUnlock()
	return unrescued == nil || !unrescued.MatchString(ua)
}

// TestIsSearchAIIsIsBotsAnswer: for every User-Agent the crawler list gives
// as an instance of a crawler, and for ones that are no crawler's, IsSearchAI
// says what the joined pattern says -- the literal pre-filter drops none --
// and what IsBot's category says.
func TestIsSearchAIIsIsBotsAnswer(t *testing.T) {
	var entries []struct {
		Pattern   string   `json:"pattern"`
		Instances []string `json:"instances"`
	}
	if err := json.Unmarshal(assets.CrawlerUserAgentsJSON, &entries); err != nil {
		t.Fatal(err)
	}
	uas := []string{
		"",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
		"curl/8.5.0",
		"python-requests/2.32.3",
		"Mozilla/5.0 " + strings.Repeat("abcdefgh ", 900),
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) " + strings.Repeat("x", 4000),
	}
	for _, e := range entries {
		uas = append(uas, e.Instances...)
	}
	checked, rescued := 0, 0
	for _, ua := range uas {
		want := searchAIReference(ua)
		if got := IsSearchAI(ua); got != want {
			t.Errorf("IsSearchAI(%.80q) = %v, the joined pattern says %v", ua, got, want)
		}
		if got := IsBot(ua, "") == SearchAI; got != want {
			t.Errorf("IsBot(%.80q) names search_ai: %v, the joined pattern says %v", ua, got, want)
		}
		checked++
		if want {
			rescued++
		}
	}
	if checked < 500 || rescued < 100 {
		t.Fatalf("%d User-Agents checked, %d of them search or AI crawlers: the list did not load", checked, rescued)
	}
	res := getCategoryREs()
	if len(res.searchGate) == 0 {
		t.Error("the pre-filter holds no literal: every User-Agent pays for the joined pattern")
	}
}
