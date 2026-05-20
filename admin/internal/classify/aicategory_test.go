package classify

import "testing"

// TestAICategory: smoke-test the 5-bucket consolidation against a handful
// of well-known user-agents.  Each bucket should match at least one UA so
// the rendered overview-table rows are not all-empty in production.
func TestAICategory(t *testing.T) {
	cases := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "search"},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "search"},
		{"Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)", "training"},
		{"Mozilla/5.0 (compatible; CCBot/2.0; +https://commoncrawl.org/faq/)", "training"},
		{"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "training"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)", "agent"},
		// Claude-Web is tagged ai-training upstream (= treated as a training
		// crawler that happens to serve user fetches).  Claude-User is the
		// pure user-agent tag.
		{"Mozilla/5.0 (compatible; Claude-User/1.0; +https://www.anthropic.com/bot.html)", "agent"},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0", ""},
		{"curl/7.85.0", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := AICategory(c.ua)
		if got != c.want {
			t.Errorf("AICategory(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
}
