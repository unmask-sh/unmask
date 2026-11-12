// Package assets: embed-only package for static resources baked into the
// unmask binary.
//
// Contents:
//   - crawler-user-agents.json        bot UA pattern source (upstream, MIT)
//   - crawler-user-agents-unmask.json unmask's own supplement to that list
//   - templates/*.html           dashboard templates
//   - static/challenge.html      challenge HTML (= canonical source; rpm/nfpm copies this to /usr/share/unmask/challenge/ for site override)
//   - iprange/*.json             official crawler IP-range snapshots from each vendor
package assets

import (
	"embed"
	"encoding/json"
	"log"
)

//go:embed crawler-user-agents.json
var upstreamCrawlerUAJSON []byte

// crawler-user-agents-unmask.json: bots the upstream list does not carry.
// Kept in a SEPARATE file, never merged into the vendored one, so refreshing
// upstream is a plain file replace and the MIT attribution in NOTICE keeps
// describing exactly what it covers.
//
// Same schema as upstream (pattern / tags / url / instances), because the
// merged result feeds the ordinary rescue path: entries land in their tag's
// group, show up in the UA-filter tab, and can be disabled per pattern like
// any other.  That matters — the hand-maintained whitelist presets removed
// earlier were a second source the UI could not switch off, so a category
// toggled off in the tab kept rescuing.  A supplement only belongs here if it
// travels the same road as upstream.
//
//go:embed crawler-user-agents-unmask.json
var unmaskCrawlerUAJSON []byte

// CrawlerUserAgentsJSON is the upstream list plus the supplement above, as one
// JSON array.  Consumers decode this single value, so every code path (tag
// lookup, group build, the crawler drill-down, the settings UI) sees the same
// bots without each having to know a second source exists.
var CrawlerUserAgentsJSON = mergeCrawlerUALists(upstreamCrawlerUAJSON, unmaskCrawlerUAJSON)

// mergeCrawlerUALists concatenates the two JSON arrays at the element level.
// A malformed or empty supplement yields the upstream bytes untouched: a bad
// edit to our own file must never cost the operator the upstream rescue list
// (that would silently start challenging Googlebot).
func mergeCrawlerUALists(upstream, extra []byte) []byte {
	if len(extra) == 0 {
		return upstream
	}
	var up, ex []json.RawMessage
	if err := json.Unmarshal(upstream, &up); err != nil {
		log.Printf("assets: upstream crawler list decode failed (%v) — supplement not merged", err)
		return upstream
	}
	if err := json.Unmarshal(extra, &ex); err != nil {
		log.Printf("assets: unmask crawler supplement decode failed (%v) — using upstream only", err)
		return upstream
	}
	merged, err := json.Marshal(append(up, ex...))
	if err != nil {
		log.Printf("assets: crawler list merge failed (%v) — using upstream only", err)
		return upstream
	}
	return merged
}

// MinCrawlerUAEntries: fewer entries with a pattern than this is not the
// upstream list.  (It carries several hundred; a truncated download or an
// error page saved under its name carries none.)
const MinCrawlerUAEntries = 100

// CrawlerUAEntries counts the entries of a crawler list that carry a pattern,
// or returns an error where raw is not such a list.
func CrawlerUAEntries(raw []byte) (int, error) {
	var data []struct {
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return 0, err
	}
	n := 0
	for _, e := range data {
		if e.Pattern != "" {
			n++
		}
	}
	return n, nil
}

// CrawlerUserAgentsWith is CrawlerUserAgentsJSON with another copy of the
// upstream list in place of the one built in -- a newer one, fetched by
// `unmask update-crawler-list` -- and the same supplement.  ok is false, and
// the built-in list is returned, where upstream is not a usable list: it
// does not decode, or holds fewer than MinCrawlerUAEntries patterns.
//
// The file named by UNMASK_CRAWLER_UA_JSON used to be taken as it was: one
// that did not decode left every list built from it empty, and the search
// crawlers the lists exist to let through were challenged; one that did
// decode replaced the supplement too.
func CrawlerUserAgentsWith(upstream []byte) (merged []byte, ok bool) {
	if n, err := CrawlerUAEntries(upstream); err != nil || n < MinCrawlerUAEntries {
		return CrawlerUserAgentsJSON, false
	}
	return mergeCrawlerUALists(upstream, unmaskCrawlerUAJSON), true
}

//go:embed templates
var Templates embed.FS

//go:embed static
var Static embed.FS

//go:embed iprange/*.json
var IPRange embed.FS
