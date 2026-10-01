package classify

import "testing"

// UABrowserLag is read off the summary the table shows, against baselines the
// caller supplies -- so nothing here depends on what today's release is.
func TestUABrowserLag(t *testing.T) {
	const curChrome, curFirefox = 150, 153
	esr := []int{140, 128}
	cases := []struct {
		ua    string
		lag   int
		ended bool
	}{
		// Chrome and Edge count against the Chromium baseline.
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36", 0, false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36", 1, false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", 11, false},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36", 41, false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", 30, false},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36", 59, false},
		// Chrome on iOS numbers its releases as Chrome does.
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1", 30, false},
		// A version past the baseline is not behind (the baseline is a floor).
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36", 0, false},
		// Firefox against its own baseline; an ESR in support is not behind.
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0", 0, false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0", 12, false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0", 0, false},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", 0, false},
		{"Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0", 101, false},
		// Internet Explorer no longer ships: no lag to count, it has ended.
		{"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", 0, true},
		{"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", 0, true},
		// Browsers that number their releases themselves are not read: the
		// Chromium inside Samsung Internet trails by design, Opera counts on
		// its own, Safari follows the OS, an app is not a browser release.
		{"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36", 0, false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0", 0, false},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15", 0, false},
		{"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/110.0.0.0 Mobile Safari/537.36 Line/13.1.0", 0, false},
		// Not browsers at all.
		{"curl/8.5.0", 0, false},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		sum := UASummary(c.ua)
		lag, ended := UABrowserLag(sum, curChrome, curFirefox, esr)
		if lag != c.lag || ended != c.ended {
			t.Errorf("UABrowserLag(%q) = (%d, %v), want (%d, %v)   [ua %.70s]", sum, lag, ended, c.lag, c.ended, c.ua)
		}
	}
}

// With no baseline to count against there is nothing to say -- and that is
// not the same as "current".
func TestUABrowserLagWithoutABaseline(t *testing.T) {
	sum := UASummary("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	if lag, ended := UABrowserLag(sum, 0, 0, nil); lag != 0 || ended {
		t.Errorf("no baseline: got (%d, %v), want (0, false)", lag, ended)
	}
	// A summary with no platform half is read the same way.
	if lag, _ := UABrowserLag("Chrome 100", 150, 0, nil); lag != 50 {
		t.Errorf("a bare browser summary: lag = %d, want 50", lag)
	}
	// A name that merely starts like a browser's is not that browser.
	for _, s := range []string{"Chrome-Lighthouse", "Firefox Focus 100", "Edge Runtime 5", "Chromebot 3"} {
		if lag, ended := UABrowserLag(s, 150, 153, nil); lag != 0 || ended {
			t.Errorf("UABrowserLag(%q) = (%d, %v), want nothing", s, lag, ended)
		}
	}
}
