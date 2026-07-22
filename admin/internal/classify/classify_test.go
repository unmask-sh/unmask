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
	const curFF = 152        // Firefox stable baseline
	ffESR := []int{140}      // exempt ESR majors
	scraper := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.7258.5 Safari/537.36"
	current := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
	oneBehind := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	safari := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"

	if !IsStaleBrowser(scraper, cur, curFF, ffESR, lag) {
		t.Error("Chrome/139 must be stale at current=150 lag=11")
	}
	if IsStaleBrowser(current, cur, curFF, ffESR, lag) {
		t.Error("Chrome/150 must not be stale")
	}
	if IsStaleBrowser(oneBehind, cur, curFF, ffESR, lag) {
		t.Error("Chrome/149 (1 behind) must not be stale at lag=11")
	}
	// Safari carries neither token -> never stale (its numbering jumped
	// 18 -> 26 and it is OS-pinned; challenging every Mac visitor would be
	// catastrophic).
	if IsStaleBrowser(safari, cur, curFF, ffESR, lag) {
		t.Error("Safari must never be treated as a stale browser")
	}
	// Boundary: exactly lag behind is stale (>=).
	edge := "Mozilla/5.0 ... Chrome/139.0.0.0 Safari/537.36"
	if !IsStaleBrowser(edge, 150, curFF, ffESR, 11) {
		t.Error("exactly lag behind must be stale")
	}
	// Feature-off inputs are inert regardless of UA.
	if IsStaleBrowser(scraper, 0, 0, ffESR, 11) || IsStaleBrowser(scraper, 150, curFF, ffESR, 0) {
		t.Error("unset currents/lag must disable the check")
	}

	// Firefox: same lag over its own current stable.
	ffOld := "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
	ffCurrent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"
	ffESRUA := "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
	ffJustStale := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0"
	if !IsStaleBrowser(ffOld, cur, curFF, ffESR, lag) {
		t.Error("Firefox/115 (EOL ESR) must be stale at current=152 lag=11")
	}
	if IsStaleBrowser(ffCurrent, cur, curFF, ffESR, lag) {
		t.Error("Firefox/152 (current) must not be stale")
	}
	// The current ESR trails stable beyond lag but is a supported, fully
	// patched release (enterprise / distro default) -> exempt.
	if IsStaleBrowser(ffESRUA, cur, curFF, ffESR, lag) {
		t.Error("Firefox ESR major must be exempt")
	}
	// The exemption is exact: one above the ESR, still >= lag behind, is stale.
	if !IsStaleBrowser(ffJustStale, cur, curFF, ffESR, lag) {
		t.Error("Firefox/141 (11 behind, not the ESR) must be stale")
	}
	// Firefox side alone can be disabled by an unset current.
	if IsStaleBrowser(ffOld, cur, 0, ffESR, lag) {
		t.Error("unset Firefox current must leave Firefox UAs untouched")
	}
}

func TestFirefoxMajor(t *testing.T) {
	cases := []struct {
		ua   string
		want int
	}{
		{"Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0", 152},
		{"Mozilla/5.0 (Android 15; Mobile; rv:140.0) Gecko/140.0 Firefox/140.0", 140},
		// iOS Firefox is WebKit (FxiOS token, no Firefox/ token) -> 0.
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/141.0 Mobile/15E148 Safari/605.1.15", 0},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36", 0},
		{"Firefox/141", 0}, // no trailing dot -> not the token shape
		{"", 0},
	}
	for _, c := range cases {
		if got := FirefoxMajor(c.ua); got != c.want {
			t.Errorf("FirefoxMajor(%q)=%d want %d", c.ua, got, c.want)
		}
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
