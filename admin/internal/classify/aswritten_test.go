package classify

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// The User-Agents that passed as the crawler "Sonic" while its name was
// matched without regard to case, and two that passed as "Fetch" and "ICBot".
const (
	uaPanasonicTV   = "Mozilla/5.0 (Linux ) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36 OPR/40.0.2207.0 OMI/4.9.0.237.DOM3-OPT.259 Model/Vestel-MB130 VSTVB MB100 FVC/2.0 (PANASONIC; MB130; ) SmartTvA/3.0.0"
	uaHypersonic    = "Mozilla/5.0 (Windows NT 10.0; rv:143.0 ) Gecko/20100101 Firefox/143.0 ,gzip(gfe);GoogleHypersonic"
	uaResearchFetch = "Mozilla/5.0 (compatible; research-fetch/1.0)"
	uaPipericBot    = "PipericBot/1.0 (+https://piperic.com/bot)"
)

// TestAsWrittenNamesAreNotFoundInsideOtherWords: a crawler's name that is
// matched as written is not found in the capitals of a television maker's
// name, at the end of another word, or at the end of another client's
// product token -- so none of these is the crawler, by tag or by name, and
// the category matcher does not hand any of them the rescue the name earns.
func TestAsWrittenNamesAreNotFoundInsideOtherWords(t *testing.T) {
	for _, ua := range []string{uaPanasonicTV, uaHypersonic} {
		if tag := LookupTag(ua); tag != "" {
			t.Errorf("LookupTag(%q) = %q: a browser's User-Agent is read as a crawler's", ua, tag)
		}
		if name, tag := LookupCrawler(ua); name != "" || tag != "" {
			t.Errorf("LookupCrawler(%q) = %q in %q, want none", ua, name, tag)
		}
		if c := IsBot(ua, "ok"); c == SearchAI {
			t.Errorf("IsBot(%q) = %v: the browser is given a crawler's pass", ua, c)
		}
	}
	// A bot of another name is still a bot (its own word says so), and is not
	// the crawler whose name its own happens to end in.
	for ua, not := range map[string]string{uaResearchFetch: "Fetch", uaPipericBot: "ICBot"} {
		if name, _ := LookupCrawler(ua); name == not {
			t.Errorf("LookupCrawler(%q) = %q: named after a crawler it is not", ua, name)
		}
		if c := IsBot(ua, "ok"); c == SearchAI {
			t.Errorf("IsBot(%q) = %v: passed on a name it does not carry", ua, c)
		}
	}
}

// TestAsWrittenPatternsStillNameTheirCrawlers: every pattern matched as
// written is an entry of the crawler list, and still matches each User-Agent
// the list gives for it -- by the tag matcher, by name, and as the nginx map
// will read it (the expression inside a case-insensitive match).  An entry
// the list drops or rewrites fails here rather than leaving a rule for a
// pattern that is gone.
func TestAsWrittenPatternsStillNameTheirCrawlers(t *testing.T) {
	var list []struct {
		Pattern   string   `json:"pattern"`
		Tags      []string `json:"tags"`
		Instances []string `json:"instances"`
	}
	if err := json.Unmarshal(sanitizeUTF8(assets.CrawlerUserAgentsJSON), &list); err != nil {
		t.Fatal(err)
	}
	byPattern := map[string]int{}
	for i, e := range list {
		byPattern[e.Pattern] = i + 1
	}
	if len(AsWrittenPatterns()) == 0 {
		t.Fatal("no pattern is matched as written: the test checks nothing")
	}
	for _, p := range AsWrittenPatterns() {
		i := byPattern[p]
		if i == 0 {
			t.Errorf("%q is matched as written and is not a pattern of the crawler list", p)
			continue
		}
		e := list[i-1]
		if MatchExpr(p) == p {
			t.Errorf("MatchExpr(%q) is the pattern itself", p)
		}
		asNginx := regexp.MustCompile(`(?i)` + MatchExpr(p))
		if len(e.Instances) == 0 {
			t.Errorf("%q: the list gives no User-Agent to hold the pattern to", p)
		}
		for _, ua := range e.Instances {
			if !asNginx.MatchString(ua) {
				t.Errorf("%q no longer matches its crawler's User-Agent %q", p, ua)
			}
			if LookupTag(ua) == "" {
				t.Errorf("LookupTag(%q) = \"\": the crawler %q names is not recognised", ua, p)
			}
		}
	}
	// A pattern that is not on the list is the pattern.
	if got := MatchExpr(`Googlebot\/`); got != `Googlebot\/` {
		t.Errorf("MatchExpr of an ordinary pattern = %q", got)
	}
}

// TestCaseStillFoldsForTheRest: the crawlers whose User-Agent differs from
// their entry by a capital, or carries the name in an address, are matched as
// before -- the reason the list is read without regard to case at all.
func TestCaseStillFoldsForTheRest(t *testing.T) {
	for ua, want := range map[string]string{
		"IAS Crawler (ias_crawler; http://integralads.com/site-indexing-policy/)":            "IAS crawler",
		"ias-sync/3.3 (former https://www.admantx.com + https://integralads.com/about-ias/)": "ADmantX",
		"Chatwork LinkPreview v1": "ChatWork LinkPreview",
	} {
		if name, tag := LookupCrawler(ua); name != want {
			t.Errorf("LookupCrawler(%q) = %q in %q, want %q", ua, name, tag, want)
		}
	}
}
