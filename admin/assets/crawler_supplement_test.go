package assets

import (
	"encoding/json"
	"testing"
)

type crawlerEntry struct {
	Pattern string   `json:"pattern"`
	Tags    []string `json:"tags"`
}

func decodeCrawlers(t *testing.T, raw []byte) []crawlerEntry {
	t.Helper()
	var out []crawlerEntry
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// TestCrawlerSupplementMerged: the shipped list is upstream + our supplement.
// The supplement exists because upstream carries Slack / Twitter / Facebook /
// Discord link-preview bots but not several that are ordinary in Japan --
// Chatwork above all -- so a site using the defaults quietly challenged the
// preview fetcher and links posted in chat rendered bare.  Whitelisting one
// class of unfurler and not another is the inconsistency this closes.
func TestCrawlerSupplementMerged(t *testing.T) {
	merged := decodeCrawlers(t, CrawlerUserAgentsJSON)
	upstream := decodeCrawlers(t, upstreamCrawlerUAJSON)
	extra := decodeCrawlers(t, unmaskCrawlerUAJSON)

	if len(merged) != len(upstream)+len(extra) {
		t.Fatalf("merged has %d entries, want %d upstream + %d supplement",
			len(merged), len(upstream), len(extra))
	}
	have := map[string][]string{}
	for _, e := range merged {
		have[e.Pattern] = e.Tags
	}
	// The supplement must reach the merged list...
	for _, want := range []string{"ChatWork LinkPreview", "WebexTeams", "NotionEmbedder"} {
		tags, ok := have[want]
		if !ok {
			t.Errorf("%q missing from the shipped crawler list", want)
			continue
		}
		// ...tagged like the upstream unfurlers, so it lands in the same group
		// and the UA-filter tab can switch it off with them.
		if len(tags) != 1 || tags[0] != "social-preview" {
			t.Errorf("%q tags = %v, want [social-preview]", want, tags)
		}
	}
	// ...without disturbing upstream.
	if _, ok := have["Googlebot\\/"]; !ok {
		t.Error("upstream entries must survive the merge")
	}
}

// TestCrawlerSupplementNoDuplicates: an entry that upstream later adds must be
// dropped from our file rather than shipped twice -- a duplicate pattern would
// render the same alternative into the nginx map twice and make the UA-filter
// tab show one bot on two rows with independent toggles.
func TestCrawlerSupplementNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range decodeCrawlers(t, upstreamCrawlerUAJSON) {
		seen[e.Pattern] = true
	}
	for _, e := range decodeCrawlers(t, unmaskCrawlerUAJSON) {
		if seen[e.Pattern] {
			t.Errorf("%q is now in upstream — drop it from crawler-user-agents-unmask.json", e.Pattern)
		}
		if e.Pattern == "" || len(e.Tags) == 0 {
			t.Errorf("supplement entry %+v needs a pattern and at least one tag", e)
		}
	}
}

// TestCrawlerMergeFallsBackToUpstream: a broken supplement must cost nothing.
// Losing the upstream list would start challenging Googlebot, so the merge
// degrades to upstream-only instead of returning something partial.
func TestCrawlerMergeFallsBackToUpstream(t *testing.T) {
	up := []byte(`[{"pattern":"Googlebot"}]`)
	for name, bad := range map[string][]byte{
		"not json":   []byte(`{{{`),
		"not array":  []byte(`{"pattern":"x"}`),
		"empty file": []byte(``),
	} {
		got := mergeCrawlerUALists(up, bad)
		if string(got) != string(up) {
			t.Errorf("%s: merge returned %q, want the upstream bytes", name, got)
		}
	}
}
