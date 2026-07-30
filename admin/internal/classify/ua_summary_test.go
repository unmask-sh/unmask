package classify

import (
	"strings"
	"testing"
)

// UASummary condenses a browser UA for the events table.  Every case here is a
// real user agent taken from fleet traffic.
func TestUASummary(t *testing.T) {
	cases := []struct{ ua, want string }{
		// Derived engines must win over the Chrome / Safari tokens they also
		// carry -- testing for those first labels every one of them wrong.
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0", "Windows 10+ · Edge 150"},
		{"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36", "Android 14 · Samsung 25"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/150.0.7871.113 Mobile/15E148 Safari/604", "iPhone 27.0 · Chrome 150"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36", "Windows 10+ · Chrome 150"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0", "Windows 10+ · Firefox 128"},

		// Devices before desktop OSes: every iOS UA says "like Mac OS X", and
		// every Android one says "Linux".
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5.2 Mobile/15E148 Safari/604.1", "iPhone 18.7 · Safari 26"},
		{"Mozilla/5.0 (iPad; CPU OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5.2 Mobile/15E148 Safari/604.1", "iPad 18.7 · Safari 26"},
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

		// The OS version is shown wherever the UA actually carries one.
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "ChromeOS 14541 · Chrome 120"},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36", "Windows 7 · Chrome 109"},
		{"Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36", "Windows 8.1 · Chrome 109"},
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

// Two OSes deliberately show no version, and both would be wrong if they did.
//
// Windows 11 reports the same "NT 10.0" as Windows 10 (Microsoft never bumped
// the kernel version), so the label says "10+" rather than picking one.
//
// macOS is worse: Safari and Chrome both freeze the field at "10_15_7" on
// every release from Catalina onward, so the number in the UA means "10.15 or
// anything newer" -- printing it would name a release the visitor is almost
// certainly not running.  Fleet traffic confirms it: every current Mac arrives
// as 10_15_7.
func TestUASummaryOmitsVersionsTheUACannotCarry(t *testing.T) {
	// Same freeze value, six macOS releases apart in reality.
	for _, ua := range []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
	} {
		got := UASummary(ua)
		if !strings.HasPrefix(got, "Mac · ") {
			t.Errorf("macOS must carry no version (the UA's is frozen): got %q", got)
		}
	}
	// Windows 10 and 11 are indistinguishable, so neither number is claimed.
	got := UASummary("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	if !strings.HasPrefix(got, "Windows 10+ · ") {
		t.Errorf("NT 10.0 must render as \"10+\" (Windows 11 reports it too): got %q", got)
	}
}
