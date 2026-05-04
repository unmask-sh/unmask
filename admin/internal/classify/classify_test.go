package classify

import "testing"

// 既知ブラウザ判定の代表ケース.
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

func TestClassify_SearchAI(t *testing.T) {
	if got := IsBot("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "ok"); got != SearchAI {
		t.Errorf("Googlebot should be SearchAI, got %v", got)
	}
	if got := IsBot("ClaudeBot/1.0", "ok"); got != SearchAI {
		t.Errorf("ClaudeBot should be SearchAI, got %v", got)
	}
}

func TestClassify_JA4Bot(t *testing.T) {
	// search_ai ではない UA + bot_* verdict
	if got := IsBot("Mozilla/5.0 ... Chrome/120 Safari/537", "bot_chrome_fake_h1"); got != JA4Bot {
		t.Errorf("bot_ verdict should give JA4Bot, got %v", got)
	}
	// search_ai UA は ja4 verdict より優先 (= 通すべき bot を弾かない)
	if got := IsBot("Googlebot/2.1", "bot_chrome_fake_h1"); got != SearchAI {
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
