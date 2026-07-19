package classify

import "testing"

// Representative cases for known-browser detection.
func TestIsKnownBrowser(t *testing.T) {
	cases := []struct {
		ua   string
		want bool
	}{
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", true},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0", true},
		{"curl/8.4.0", false},
		{"python-requests/2.31.0", false},
		{"Googlebot/2.1 (+http://www.google.com/bot.html)", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsKnownBrowser(c.ua); got != c.want {
			t.Errorf("IsKnownBrowser(%q)=%v want %v", c.ua, got, c.want)
		}
	}
}

func TestIsOldBrowser(t *testing.T) {
	if !IsOldBrowser("Mozilla/5.0 ... Chrome/15.0 Safari/537.36") {
		t.Error("Chrome 15 should be old")
	}
	if IsOldBrowser("Mozilla/5.0 ... Chrome/120.0 Safari/537.36") {
		t.Error("Chrome 120 should not be old")
	}
}

func TestChromeMajor(t *testing.T) {
	cases := []struct {
		ua   string
		want int
	}{
		// The 2026-07-15 scraper's pinned UA.
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.7258.5 Safari/537.36", 139},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36", 150},
		// Edge / Opera carry the shared Chrome token.
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0", 139},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 OPR/124.0.0.0", 138},
		// Non-Chromium and non-browser: no Chrome token -> 0.
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", 0},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", 0},
		{"curl/8.4.0", 0},
		{"", 0},
	}
	for _, c := range cases {
		if got := ChromeMajor(c.ua); got != c.want {
			t.Errorf("ChromeMajor(%q)=%d want %d", c.ua, got, c.want)
		}
	}
}

func TestIsStaleBrowser(t *testing.T) {
	const cur, lag = 150, 11 // catch <=139, the incident threshold
	scraper := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.7258.5 Safari/537.36"
	current := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
	oneBehind := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	safari := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"

	if !IsStaleBrowser(scraper, cur, lag) {
		t.Error("Chrome/139 must be stale at current=150 lag=11")
	}
	if IsStaleBrowser(current, cur, lag) {
		t.Error("Chrome/150 must not be stale")
	}
	if IsStaleBrowser(oneBehind, cur, lag) {
		t.Error("Chrome/149 (1 behind) must not be stale at lag=11")
	}
	// Safari has no Chrome token -> never stale (would be catastrophic to
	// challenge every Mac visitor).
	if IsStaleBrowser(safari, cur, lag) {
		t.Error("Safari must never be treated as a stale Chrome")
	}
	// Boundary: exactly lag behind is stale (>=).
	edge := "Mozilla/5.0 ... Chrome/139.0.0.0 Safari/537.36"
	if !IsStaleBrowser(edge, 150, 11) {
		t.Error("exactly lag behind must be stale")
	}
	// Feature-off inputs are inert regardless of UA.
	if IsStaleBrowser(scraper, 0, 11) || IsStaleBrowser(scraper, 150, 0) {
		t.Error("unset current/lag must disable the check")
	}
}

func TestClassify_SearchAI(t *testing.T) {
	if got := IsBot("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "ok"); got != SearchAI {
		t.Errorf("Googlebot should be SearchAI, got %v", got)
	}
	if got := IsBot("ClaudeBot/1.0", "ok"); got != SearchAI {
		t.Errorf("ClaudeBot should be SearchAI, got %v", got)
	}
}

func TestClassify_JA4Bot(t *testing.T) {
	// non-search_ai UA + ja4Action="bot"
	if got := IsBot("Mozilla/5.0 ... Chrome/120 Safari/537", "bot"); got != JA4Bot {
		t.Errorf(`action="bot" should give JA4Bot, got %v`, got)
	}
	// suspect is also treated as JA4Bot
	if got := IsBot("Mozilla/5.0 ... Chrome/120 Safari/537", "suspect"); got != JA4Bot {
		t.Errorf(`action="suspect" should give JA4Bot, got %v`, got)
	}
	// search_ai UA takes precedence over the ja4 action (= don't block bots that should be allowed)
	if got := IsBot("Googlebot/2.1", "bot"); got != SearchAI {
		t.Errorf("search_ai should win over JA4 bot, got %v", got)
	}
}

func TestClassify_UserDev(t *testing.T) {
	if got := IsBot("curl/8.4.0", "ok"); got != UserDev {
		t.Errorf("curl should be UserDev, got %v", got)
	}
	if got := IsBot("python-requests/2.31.0", "ok"); got != UserDev {
		t.Errorf("python-requests should be UserDev, got %v", got)
	}
	if got := IsBot("HeadlessChrome/120.0", "ok"); got != UserDev {
		t.Errorf("HeadlessChrome should be UserDev, got %v", got)
	}
}

func TestClassify_Human(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
	if got := IsBot(ua, "ok"); got != Human {
		t.Errorf("human Safari with ok verdict should be Human, got %v", got)
	}
}
