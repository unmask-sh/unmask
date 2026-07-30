package classify

import "testing"

// UASummary condenses a browser UA for the events table.  Every case here is a
// real user agent taken from fleet traffic.
func TestUASummary(t *testing.T) {
	cases := []struct{ ua, want string }{
		// Derived engines must win over the Chrome / Safari tokens they also
		// carry -- testing for those first labels every one of them wrong.
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0", "Windows · Edge 150"},
		{"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36", "Android 14 · Samsung 25"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/150.0.7871.113 Mobile/15E148 Safari/604", "iPhone · Chrome 150"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36", "Windows · Chrome 150"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0", "Windows · Firefox 128"},

		// Devices before desktop OSes: every iOS UA says "like Mac OS X", and
		// every Android one says "Linux".
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5.2 Mobile/15E148 Safari/604.1", "iPhone · Safari 26"},
		{"Mozilla/5.0 (iPad; CPU OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5.2 Mobile/15E148 Safari/604.1", "iPad · Safari 26"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", "Mac · Safari 17"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "Linux · Chrome 126"},

		// The Android phone/tablet split rides the "Mobile" token...
		{"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36", "Android 10 · Chrome 140"},
		{"Mozilla/5.0 (Linux; Android 13; SM-X200) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36", "Android 13 Tab · Chrome 140"},
		// ...except in an in-app WebView, which drops Mobile on phones too.
		{"Mozilla/5.0 (Linux; Android 16; SM-S901N Build/BP2A.250605.031.A3; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.0.0 Whale/1.0", "Android 16 · Chrome 128"},

		// The version is kept because unmask's own decisions turn on it: this
		// is the handset population the header-integrity axis had to stop
		// challenging (Sec-CH-UA shipped in Chromium 89).
		{"Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.181 Mobile Safari/537.36", "Android 6 · Chrome 88"},
	}
	for _, c := range cases {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60s...)\n got %q\nwant %q", c.ua, got, c.want)
		}
	}
}

// Anything that is not a recognisable browser must NOT summarise, so the table
// falls back to the raw string.  The events log is a bot-hunting surface: a UA
// that does not fit the browser shape is exactly the one whose bytes the
// operator wants to read, and folding those into an "Other" bucket would throw
// the evidence away.
func TestUASummaryKeepsNonBrowsersRaw(t *testing.T) {
	for _, ua := range []string{
		"curl/8.0",
		"python-requests/2.31.0",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"NotificationExtension/3 CFNetwork/3826.600.41.2.1 Darwin/24.6.0",
		"Mozilla/5.0 (compatible; ChatWork LinkPreview/1.1; +https://go.chatwork.com/)",
		"",
	} {
		if got := UASummary(ua); got != "" {
			t.Errorf("UASummary(%q) = %q, want \"\" so the caller keeps the raw UA", ua, got)
		}
	}
}
