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
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", "Mac 10.15+ · Safari 17"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "Linux x86_64 · Chrome 126"},

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
	// A UA that is neither a browser NOR a listed crawler keeps its raw form,
	// which is the informative one for an unknown client.  Listed crawlers are
	// summarised by name instead -- see TestUASummaryNamesKnownCrawlers.
	for _, ua := range []string{
		"curl/8.0",
		"python-requests/2.31.0",
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
func TestUASummaryMarksVersionsTheUAPinsAtAFloor(t *testing.T) {
	// Both platforms freeze their version field at a value that means "this
	// release or anything newer", and both are shown WITH the value and a "+".
	// The column reports what the client said; the marker carries the
	// uncertainty.  Dropping the number instead (which macOS used to do) made
	// two identical situations render differently for no reason the operator
	// could see.
	for _, ua := range []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
	} {
		if got := UASummary(ua); !strings.HasPrefix(got, "Mac 10.15+ · ") {
			t.Errorf("the frozen macOS value must render as \"10.15+\": got %q", got)
		}
	}
	got := UASummary("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	if !strings.HasPrefix(got, "Windows 10+ · ") {
		t.Errorf("NT 10.0 must render as \"10+\" (Windows 11 reports it too): got %q", got)
	}
}

// A UA on the crawler list summarises to the crawler's NAME.  That name is
// what an operator scans the hunt log for: several crawlers (Googlebot,
// Bingbot) ship a full Chrome-shaped UA that would otherwise read as an
// ordinary desktop browser, and a request claiming a crawler while sitting in
// the challenge log is exactly the spoof an operator is looking for.
func TestUASummaryNamesKnownCrawlers(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot"},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "bingbot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot", "GPTBot"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.50q) = %q, want %q", c.ua, got, c.want)
		}
	}
	// A Chrome-shaped crawler UA must not summarise as plain Chrome.
	const chromeShaped = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	if got := UASummary(chromeShaped); got != "Googlebot" {
		t.Errorf("a Chrome-shaped Googlebot summarised as %q -- the crawler identity was lost", got)
	}
}

// In-app browsers.  These are humans arriving through an app's embedded
// WebView, and several carry no Chrome/Safari version token, so they fell
// through every branch and left the row with no summary at all -- a raw UA
// sitting among "platform · browser" rows.  All four of these were pulled
// from live fleet traffic.
func TestUASummaryNamesInAppBrowsers(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari Line/26.11.0",
			"iPhone 18.7 · LINE 26"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 26_5_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Version/26.5.2 YJApp-IOS jp.co.yahoo.ipn.appli/4.168.0",
			"iPhone 26.5 · Yahoo! JAPAN App"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 26_5_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/431.2.950282168 Mobile/15E148 Safari/604.1",
			"iPhone 26.5 · Google App 431"},
		{"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 10.0; Trident/3.1)",
			"Windows 10+ · IE 7"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
}

// A named app wins over the engine token it embeds: an Android WebView sends
// both, and "Chrome 120" is the least distinguishing thing a UA can say while
// the app names a real cohort.  iOS already answered this way, so this is also
// what makes one app read the same on both platforms.  A plain Safari / Chrome
// UA must be unaffected by any of this.
func TestUASummaryNamesTheAppOverTheEngine(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			"Windows 10+ · Chrome 126"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			"iPhone 17.0 · Safari 17"},
		// Chrome token present alongside an app token: the app wins.
		{"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 Instagram 300.0.0",
			"Android 13 · Instagram 300"},
		// A bare major with no minor ("Chrome/131", not "131.0.0.0") is how
		// simplified and forged UAs state themselves; the claim renders
		// as-is instead of falling through to no browser at all.
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36",
			"Windows 10+ · Chrome 131"},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128",
			"Linux x86_64 · Firefox 128"},
		// Same app, both platforms, same answer (jp: 650 Android + 1915 iOS).
		{"Mozilla/5.0 (Linux; Android 13; SM-S908N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 Line/13.5.0",
			"Android 13 · LINE 13"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1 Line/13.5.0",
			"iPhone 16.6 · LINE 13"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
}

// A listed crawler's name comes from the curated list even when the UA has no
// bot-shaped product token of its own: Google-Extended's UA only says "bot"
// inside its info URL, and the self-declared scan used to run first and
// extract exactly that -- an amber listed badge captioned "bot".  The list is
// authoritative for names; the scan only covers bots the list does not know.
func TestUASummaryPrefersTheListName(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (compatible; Google-Extended/1.0; +http://www.google.com/bot.html)",
			"Google-Extended"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.3; +https://openai.com/gptbot)",
			"GPTBot"},
		// Not on the list: the self-declared scan still names it.
		{"Mozilla/5.0 (compatible; TotallyNewBot/9.9; +http://example.com/info)",
			"TotallyNewBot"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60q) = %q, want %q", c.ua, got, c.want)
		}
	}
}

// The platform glyph is derived from the SUMMARY, so it can never contradict
// the text it sits next to.  It is decoration: every platform still spells its
// name, and a summary with no recognisable platform (a crawler name, an
// unknown client) gets no icon rather than a misleading one.
func TestUAPlatformIcon(t *testing.T) {
	for _, c := range []struct{ summary, want string }{
		{"Windows 10+ · Chrome 126", "🪟"},
		{"Mac 10.15+ · Safari 17", "🍎"},
		{"iPhone 18.7 · LINE 26", "🍎"},
		{"iPad 17.0 · Safari 17", "🍎"},
		{"Android 13 · Chrome 120", "🤖"},
		{"Linux · Chrome 126", "🐧"},
		{"Ubuntu · Firefox 128", "🐧"},
		{"ChromeOS 120 · Chrome 120", "🌐"},
		{"Googlebot", ""}, // a crawler name is not a platform
		{"", ""},
	} {
		if got := UAPlatformIcon(c.summary); got != c.want {
			t.Errorf("UAPlatformIcon(%q) = %q, want %q", c.summary, got, c.want)
		}
	}
}

// Browser identity is shown as a brand colour, not an emoji: no glyph reads as
// "Chrome" or "Edge" the way 🍎 reads as Apple, so an icon set would be a
// legend to memorise rather than a shortcut.  The colour is decoration on top
// of the name, so an unknown browser simply gets none.
func TestUABrowserColor(t *testing.T) {
	for _, c := range []struct{ summary, want string }{
		{"Windows 10+ · Chrome 126", "#4285f4"},
		{"Mac 10.15+ · Safari 17", "#1b9df0"},
		{"Ubuntu · Firefox 128", "#ff7139"},
		{"Windows 10+ · Edge 126", "#0f7c9e"},
		{"iPhone 18.7 · LINE 26", "#06c755"},
		{"iPhone 26.5 · Yahoo! JAPAN App", "#ff0033"},
		{"Windows 10+ · IE 7", "#94a3b8"},
		{"Windows 10+ · Netscape 4", ""}, // unknown browser: no colour invented
		{"Googlebot", ""},                // no browser part at all
		{"", ""},
	} {
		if got := UABrowserColor(c.summary); got != c.want {
			t.Errorf("UABrowserColor(%q) = %q, want %q", c.summary, got, c.want)
		}
	}
}

// Self-identified bots.  crawler-user-agents.json is curated and cannot keep
// up: in production the two biggest unsummarised UAs were
// Amzn-SearchBot and AzureAI-SearchBot, thousands of requests over two days,
// neither on the
// list.  They all name themselves, and several wrap that name in a full
// Chrome-shaped UA that would otherwise read as an ordinary desktop browser.
func TestUASummaryNamesSelfDeclaredBots(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amzn-SearchBot/0.1) Chrome/119.0.6045.214 Safari/537.36", "Amzn-SearchBot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; AzureAI-SearchBot/1.0;", "AzureAI-SearchBot"},
		{"Mozilla/5.0 (compatible; MarubeniBot/1.0)", "MarubeniBot"},
		{"peer39_crawler/1.0", "peer39_crawler"},
		{"TLM-Audit-Scanner/1.0", "TLM-Audit-Scanner"},
		{"Mozilla/5.0 official-url-checker/1.0", "official-url-checker"},
		{"Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", "CensysInspect"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
	// An ordinary browser must not be read as a bot.
	const human = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	if got := UASummary(human); got != "Windows 10+ · Chrome 126" {
		t.Errorf("a plain Chrome UA summarised as %q", got)
	}
}

// A UA that names a platform but carries no browser token (truncated or
// hand-built) summarises to the platform alone: the row keeps the shape of
// its neighbours and the missing half is itself the signal.
func TestUASummaryFallsBackToPlatformAlone(t *testing.T) {
	// A UA with no browser token AND no AppleWebKit either: nothing to name.
	// (An AppleWebKit-only UA is a WebView -- see
	// TestUASummaryNamesBareIOSWebView.)
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Windows 10+"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "Linux x86_64"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60q) = %q, want %q", c.ua, got, c.want)
		}
	}
	// With neither a platform nor a self-named client, the raw string is
	// still what the row shows.  (okhttp names itself, so it is summarised --
	// see TestUASummaryNamesAndroidAppClients.)
	for _, ua := range []string{"curl/8.0", "Mozilla/5.0", "pc"} {
		if got := UASummary(ua); got != "" {
			t.Errorf("UASummary(%q) = %q, want \"\" so the caller keeps the raw string", ua, got)
		}
	}
}

// macOS freezes its version at 10_15_7 from Catalina onward, so that one value
// means "10.15 or anything newer".  It is still shown -- with a "+", the same
// way "Windows NT 10.0" (equally 10-or-11) renders as "Windows 10+".  This
// column reports what the client said; the marker carries the uncertainty
// instead of the value being dropped.
func TestUASummaryShowsRealMacVersions(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", "Mac 10.15+ · Safari 17"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "Mac 12.0 · Chrome 126"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0 Safari/537.36", "Mac 10.12 · Chrome 60"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
}

// A desktop-Linux UA carries no OS version -- "X11" is a bare token with no
// number behind it, and there is no kernel or distro release in the string.
// The architecture is the one real fact it does hold, and it earns the space:
// 32-bit desktops effectively do not exist any more, so an i686 row is itself
// worth noticing.
func TestUASummaryShowsLinuxArchitecture(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			"Linux x86_64 · Chrome 126"},
		{"Mozilla/5.0 (X11; Linux i686; rv:1.9.6.20) Gecko/2010 Firefox/3.6",
			"Linux i686 · Firefox 3"},
		{"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
			"Ubuntu x86_64 · Firefox 128"},
		{"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
			"Linux aarch64 · Chrome 120"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
	// No architecture named: the platform stands alone rather than inventing one.
	const bare = "Mozilla/5.0 (X11; Linux) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	if got := UASummary(bare); got != "Linux · Chrome 126" {
		t.Errorf("UASummary(bare Linux) = %q, want %q", got, "Linux · Chrome 126")
	}
}

// Windows names its release in several shapes, and the summary reports every
// one of them.  Live traffic carries 174 "Windows 98" hits and 108 that claim
// "Windows NT 11.0" -- a version that has never existed.  Neither is dropped:
// this column says what the client said, and an impossible value is worth
// seeing rather than hiding.
func TestUASummaryReportsEveryWindowsShape(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (compatible; MSIE 6.0; Windows 98; Win 9x 4.90; Trident/4.0)", "Windows 98 · IE 6"},
		{"Mozilla/5.0 (compatible; MSIE 6.0; Windows 95)", "Windows 95 · IE 6"},
		{"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36", "Windows NT 11.0 · Chrome 120"},
		{"Mozilla/5.0 (Windows NT 4.0) AppleWebKit/537.36 Chrome/60.0 Safari/537.36", "Windows NT 4.0 · Chrome 60"},
		{"Mozilla/5.0 (Windows NT 5.0) Gecko/20100101 Firefox/40.0", "Windows 2000 · Firefox 40"},
		{"Mozilla/5.0 (Windows NT 5.01) Gecko/20100101 Firefox/40.0", "Windows XP · Firefox 40"},
		{"Mozilla/5.0 (Windows NT 5.2) AppleWebKit/537.36 Chrome/60.0 Safari/537.36", "Windows XP x64 · Chrome 60"},
		{"Mozilla/5.0 (Windows CE) Opera/9.0", "Windows CE · Opera 9"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
}

// Android's runtime and HTTP libraries are not browsers, and saying so is the
// point: a Dalvik UA is an app making a plain HTTP request, with no page being
// rendered.  Live traffic carries both, and neither was summarised before --
// the rows showed a raw string among "platform · browser" neighbours.
func TestUASummaryNamesAndroidAppClients(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Dalvik/2.1.0 (Linux; U; Android 17; Pixel 8a Build/CP2A.260705.006)", "Android 17 · App (Dalvik)"},
		{"Dalvik/2.1.0 (Linux; U; Android 9.0; ZTE BA520 Build/MRA58K)", "Android 9 · App (Dalvik)"},
		{"okhttp/5.3.0", "okhttp 5"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.60q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
}

// The "Tab" suffix keys off the absence of "Mobile", which a Dalvik UA never
// carries -- so every app request from a phone was being labelled a tablet
// (live traffic shows Pixel 8a / 9a arriving as "Android 17 Tab").
func TestAndroidTabSuffixSkipsAppRuntimes(t *testing.T) {
	if got := UASummary("Dalvik/2.1.0 (Linux; U; Android 17; Pixel 9a Build/CP2A.260705.006)"); strings.Contains(got, "Tab") {
		t.Errorf("a phone's app request was labelled a tablet: %q", got)
	}
	// A real tablet browser UA still gets it.
	if got := UASummary("Mozilla/5.0 (Linux; Android 14; SM-X200) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"); !strings.Contains(got, "Tab") {
		t.Errorf("a tablet browser UA lost its Tab marker: %q", got)
	}
}

// A bare iOS WebView: AppleWebKit + "Mobile/" and nothing else.  That is what
// WKWebView sends when the host app sets no UA of its own, and it is the
// second-largest iOS shape on live traffic (1779 hits).  Safari always appends
// "Version/x Safari/y", so the absence of those tokens is the tell rather than
// a guess -- and the row was previously left with no browser at all.
func TestUASummaryNamesBareIOSWebView(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
			"iPhone 18.5 · In-app browser"},
		// The macOS shape of the same thing: AppleWebKit and nothing after it.
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)",
			"Mac 10.15+ · In-app browser"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			"Mac 10.15+ · In-app browser"},
		// A Mac Firefox UA also lacks "Safari/" -- it must not be swept up.
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:109.0) Gecko/20100101 Firefox/115.0",
			"Mac 10.13 · Firefox 115"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.58q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
	// An app that DOES name itself keeps its name, and real Safari stays
	// Safari: the WebView branch runs after both.
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (iPad; CPU OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 YJApp-IOS jp.co.yahoo.ipn.appli/4.1",
			"iPad 15.6 · Yahoo! JAPAN App"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			"iPhone 17.0 · Safari 17"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari Line/26.11.0",
			"iPhone 18.7 · LINE 26"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.55q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
}

// Opera ships three shapes and only the current one was recognised.  The
// Presto-era forms account for 745 hits on live traffic -- and an Opera 10 in
// 2026 is itself worth seeing, which it cannot be while the row shows no
// browser at all.  In "Opera/9.80 ... Version/12.16" the real release is the
// Version/ number; Opera/ is frozen at 9.x.
func TestUASummaryNamesEveryOperaShape(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Opera/9.98.(Windows NT 6.1; fr-CA) Presto/2.9.187 Version/10.00", "Windows 7 · Opera 10"},
		{"Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.16", "Windows Vista · Opera 12"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 OPR/106.0", "Windows 10+ · Opera 106"},
		{"Opera/9.80 (J2ME/MIDP; Opera Mini/9.80) Presto/2.5.25", "Opera Mini"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.58q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
	// Chrome must not be read as Opera: OPR/ is the only Opera token a
	// Chromium UA carries.
	if got := UASummary("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"); got != "Windows 10+ · Chrome 126" {
		t.Errorf("a plain Chrome UA summarised as %q", got)
	}
}

// macOS version separators: "10_15_7" (Safari / Chrome) and "10.13" (Firefox).
// Matching only "_" truncated the Firefox form to its major number -- "Mac OS
// X 10.13" was reported as "Mac 10", which is not a release at all.
func TestUASummaryReadsBothMacVersionSeparators(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:109.0) Gecko/20100101 Firefox/115.0", "Mac 10.13 · Firefox 115"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:78.0) Gecko/20100101 Firefox/78.0", "Mac 10.10 · Firefox 78"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36", "Mac 12.0 · Chrome 126"},
	} {
		if got := UASummary(c.ua); got != c.want {
			t.Errorf("UASummary(%.58q)\n  = %q\n want %q", c.ua, got, c.want)
		}
	}
}

// IE gets a drawn mark like the live browsers.  A browser that stopped
// shipping in 2022 is mostly a forged UA, so the row should be as
// identifiable at a glance as a real one.
func TestUABrowserIconCoversIE(t *testing.T) {
	if got := UABrowserIcon("Windows 95 · IE 6"); got != "ie" {
		t.Errorf("IE icon = %q, want %q", got, "ie")
	}
	if got := UABrowserIcon("Windows 10+ · Trident 3.1"); got != "ie" {
		t.Errorf("Trident icon = %q, want %q", got, "ie")
	}
	// An app with no drawn mark still gets none (it falls back to the dot).
	if got := UABrowserIcon("Android 13 · Instagram 300"); got != "" {
		t.Errorf("Instagram should have no drawn mark, got %q", got)
	}
}

// Every browser that carries real traffic gets a drawn mark, and the in-app
// cases get one per platform: a WebView on an iPhone and an app request on
// Android are different things to look at, and neither is a browser the
// visitor chose.  Live traffic: iOS 257, macOS 90, Android (Dalvik) 159.
func TestUABrowserIconCoversTheDrawnSet(t *testing.T) {
	for _, c := range []struct{ summary, want string }{
		{"Windows 10+ · Chrome 126", "chrome"},
		{"Windows 10+ · Edge 126", "edge"},
		{"Ubuntu x86_64 · Firefox 128", "firefox"},
		{"Mac 12.0 · Safari 17", "safari"},
		{"Windows 7 · Opera 10", "opera"},
		{"Windows 95 · IE 6", "ie"},
		{"iPhone 18.5 · In-app browser", "wv-apple"},
		{"Mac 10.15+ · In-app browser", "wv-apple"},
		{"Android 17 · App (Dalvik)", "wv-android"},
		// Named in-app browsers get a mark once they carry real traffic:
		// the Google app (2379 hits) and the Yahoo! JAPAN app (2416).
		{"iPhone 26.5 · Google App 431", "gsa"},
		{"iPad 15.6 · Yahoo! JAPAN App", "yjapp"},
		// LINE carries 2565 requests on jp once Android stops reading as
		// Chrome, which is well past the point of deserving a mark.
		{"iPhone 18.7 · LINE 26", "line"},
		{"Android 13 · LINE 13", "line"},
		// The rest keep the brand dot: a mark nobody meets is sprite noise.
		{"Android 13 · Instagram 300", ""},
		{"Googlebot", ""},
	} {
		if got := UABrowserIcon(c.summary); got != c.want {
			t.Errorf("UABrowserIcon(%q) = %q, want %q", c.summary, got, c.want)
		}
	}
}
