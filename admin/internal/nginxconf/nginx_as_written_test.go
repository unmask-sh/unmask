package nginxconf

import (
	"os"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
)

// TestNginxReadsACrawlersNameAsTheDaemonDoes: a real nginx, the render, and
// the User-Agents the rescue is decided on -- the rescue map's answer beside
// the daemon's (classify.IsBot), for each.
//
// A crawler-list pattern is matched without regard to case by both, except
// the few that are matched as written (classify.MatchExpr): those reach
// nginx as a group that restores case inside the map's "~*", which PCRE and
// PCRE2 have to read as Go's regexp does.  So the crawler still passes on
// its name, a browser whose User-Agent holds the name's letters in another
// word does not, and a crawler whose vendor changed a capital still does.
//
// Skipped unless UNMASK_TEST_NGINX and UNMASK_TEST_NGINX_MODULE are set:
// `make test-nginx-accepts` sets both.
func TestNginxReadsACrawlersNameAsTheDaemonDoes(t *testing.T) {
	bin, mod := os.Getenv("UNMASK_TEST_NGINX"), os.Getenv("UNMASK_TEST_NGINX_MODULE")
	if bin == "" || mod == "" {
		t.Skip("UNMASK_TEST_NGINX / UNMASK_TEST_NGINX_MODULE are not set")
	}
	ask := startNginx(t, bin, mod, "", "$unmask_search_bot_ua")
	rescued := 0
	for _, c := range []struct {
		ua, want, why string
	}{
		// Matched as written: the crawler, in the case its entry is written in.
		{"Mozilla/5.0 (compatible; Sonic/1.0; http://www.yama.info.waseda.ac.jp/~crawler/info.html)", "1", "the crawler the pattern names"},
		{"Mozilla/5.0 (compatible; RankSonicSiteAuditor/1.0; +https://ranksonic.com/ranksonic_sab.html)", "1", "another the same entry lists"},
		{"Fetch/2.0a (CMS Detection/Web/SEO analysis tool, see http://guess.scritch.org)", "1", "the crawler the pattern names"},
		{"Mozilla/5.0 (compatible; ICBot/0.1; +https://ideasandcode.xyz", "1", "the crawler the pattern names"},
		// ... and not the name's letters inside another word.
		{"Mozilla/5.0 (Linux ) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36 OPR/40.0.2207.0 OMI/4.9.0.237.DOM3-OPT.259 Model/Vestel-MB130 VSTVB MB100 FVC/2.0 (PANASONIC; MB130; ) SmartTvA/3.0.0", "0", "a television's browser, the maker's name in capitals"},
		{"Mozilla/5.0 (Windows NT 10.0; rv:143.0 ) Gecko/20100101 Firefox/143.0 ,gzip(gfe);GoogleHypersonic", "0", "a word that ends in the name"},
		{"Mozilla/5.0 (compatible; sonic/1.0)", "0", "the name in another case"},
		{"Mozilla/5.0 (compatible; research-fetch/1.0)", "0", "a product token that ends in fetch/"},
		{"PipericBot/1.0 (+https://piperic.com/bot)", "0", "a bot whose name ends in icBot/"},
		// Every other pattern: without regard to case, as before.
		{"IAS Crawler (ias_crawler; http://integralads.com/site-indexing-policy/)", "1", "a crawler whose vendor writes a capital its entry does not"},
		{"Mozilla/5.0 (compatible;petalbot;+https://webmaster.petalsearch.com/site/petalbot)", "1", "a crawler's name in lower case"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36", "0", "a browser"},
	} {
		got := ask(false, map[string]string{"User-Agent": c.ua})
		if got != c.want {
			t.Errorf("nginx's rescue map on %q (%s) = %q, want %q", c.ua, c.why, got, c.want)
		}
		daemon := "0"
		if classify.IsBot(c.ua, "ok") == classify.SearchAI {
			daemon = "1"
		}
		if daemon != got {
			t.Errorf("%q (%s): nginx's rescue map says %q, the daemon %q", c.ua, c.why, got, daemon)
		}
		if got == "1" {
			rescued++
		}
	}
	if rescued != 6 {
		t.Errorf("%d of the User-Agents are rescued, want 6: the table does not test what it says", rescued)
	}
}
