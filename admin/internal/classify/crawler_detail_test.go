package classify

import "testing"

func TestLookupCrawler(t *testing.T) {
	cases := []struct {
		ua       string
		wantName string // "" = expect a non-empty name (don't pin the exact string)
		wantTag  string // "" = expect any non-empty tag; "-" = expect empty (not a crawler)
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot", "search-engine"},
		{"Googlebot-Image/1.0", "Googlebot-Image", "search-engine"},
		{"Mozilla/5.0 AppleWebKit (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "", "search-engine"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", "", "-"},
		{"", "", "-"},
	}
	for _, c := range cases {
		name, tag := LookupCrawler(c.ua)
		if c.wantTag == "-" {
			if tag != "" || name != "" {
				t.Errorf("LookupCrawler(%q) = (%q,%q), want a non-crawler (\"\",\"\")", c.ua, name, tag)
			}
			continue
		}
		if tag == "" {
			t.Errorf("LookupCrawler(%q) tag is empty, want a crawler tag", c.ua)
		}
		if c.wantTag != "" && tag != c.wantTag {
			t.Errorf("LookupCrawler(%q) tag = %q, want %q", c.ua, tag, c.wantTag)
		}
		if name == "" || name == "other" {
			t.Errorf("LookupCrawler(%q) name = %q, want a concrete crawler", c.ua, name)
		}
		if c.wantName != "" && name != c.wantName {
			t.Errorf("LookupCrawler(%q) name = %q, want %q", c.ua, name, c.wantName)
		}
	}
}

func TestCrawlerDisplayName(t *testing.T) {
	cases := map[string]string{
		`Googlebot\/`:           "Googlebot",
		`Googlebot-Mobile`:      "Googlebot-Mobile",
		`AdsBot-Google([^-]|$)`: "AdsBot-Google",
		`filterdb\.iss\.net\/c`: "filterdb.iss.net/c",
		`BLP_bbot`:              "BLP_bbot",
		`^$`:                    "other", // pathological: nothing literal -> fallback
	}
	for pat, want := range cases {
		if got := crawlerDisplayName(pat); got != want {
			t.Errorf("crawlerDisplayName(%q) = %q, want %q", pat, got, want)
		}
	}
}
