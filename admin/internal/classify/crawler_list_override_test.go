package classify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

// UNMASK_CRAWLER_UA_JSON names a newer copy of the upstream crawler list.
// The file was taken as it was: one that did not decode -- a download cut
// short, an error page saved under the name -- left every list built from it
// empty, and the search crawlers the lists exist to let through were
// challenged; one that did decode took the place of unmask's supplement too.
func TestCrawlerListOverride(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rescues := func(raw []byte, ua string) bool {
		res := buildCategoryREs(raw)
		return res.searchAI != nil && res.searchAI.MatchString(ua)
	}
	if !rescues(assets.CrawlerUserAgentsJSON, googlebotUA) {
		t.Fatal("the built-in list does not rescue Googlebot; the checks below would prove nothing")
	}

	// No file named: the built-in list.
	if got := crawlerListFrom(""); string(got) != string(assets.CrawlerUserAgentsJSON) {
		t.Error("with no file named the list is not the built-in one")
	}

	// Files that are not the list: the built-in one stands.
	for name, body := range map[string]string{
		"an error page":        "<!doctype html><title>502</title>" + strings.Repeat("<p>bad gateway</p>", 200),
		"a download cut short": string(assets.CrawlerUserAgentsJSON[:len(assets.CrawlerUserAgentsJSON)/2]),
		"an empty array":       "[]" + strings.Repeat(" ", 2000),
		"a list of three":      `[{"pattern":"OneBot"},{"pattern":"TwoBot"},{"pattern":"ThreeBot"}]` + strings.Repeat(" ", 2000),
	} {
		got := crawlerListFrom(write("bad.json", body))
		if string(got) != string(assets.CrawlerUserAgentsJSON) {
			t.Errorf("%s: taken as the crawler list", name)
		}
		if !rescues(got, googlebotUA) {
			t.Errorf("%s: Googlebot is not rescued from the list in use", name)
		}
	}
	if got := crawlerListFrom(filepath.Join(dir, "absent.json")); !rescues(got, googlebotUA) {
		t.Error("a file that is not there: Googlebot is not rescued from the list in use")
	}

	// A usable copy of the upstream list: taken, and the supplement with it.
	var upstream []map[string]any
	if err := json.Unmarshal(assets.CrawlerUserAgentsJSON, &upstream); err != nil {
		t.Fatal(err)
	}
	var newer []map[string]any
	for _, e := range upstream {
		p, _ := e["pattern"].(string)
		if p == "NotionEmbedder" || p == "ChatWork LinkPreview" {
			continue // the supplement's: an upstream copy does not carry them
		}
		newer = append(newer, e)
	}
	newer = append(newer, map[string]any{"pattern": "BrandNewSearchBot", "tags": []string{"search-engine"}})
	body, err := json.Marshal(newer)
	if err != nil {
		t.Fatal(err)
	}
	got := crawlerListFrom(write("newer.json", string(body)))
	n, err := assets.CrawlerUAEntries(got)
	if err != nil {
		t.Fatalf("the list in use does not decode: %v", err)
	}
	if n <= len(newer) {
		t.Errorf("the list in use holds %d patterns, the file %d: the supplement was not added", n, len(newer))
	}
	detail := string(got)
	for _, want := range []string{"BrandNewSearchBot", "NotionEmbedder", "ChatWork LinkPreview"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the list in use lacks %q (the file's new entry, or the supplement's)", want)
		}
	}
	if !rescues(got, "Mozilla/5.0 (compatible; BrandNewSearchBot/1.0)") || !rescues(got, googlebotUA) {
		t.Error("the file's new search crawler, or Googlebot, is not rescued from the list in use")
	}
}
