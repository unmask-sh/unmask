// review-crawler-list: diff the upstream crawler-user-agents.json against the
// embedded copy.
//
// Use as a sanity check before enabling auto-update, or to confirm the
// upstream isn't broken.
// Output:
//   == added (= patterns added upstream) ==
//     <regex>     <instance count>
//   == removed (= patterns dropped upstream) ==
//     <regex>
//   == summary ==
//     embed: N entries, upstream: M entries, added=A, removed=R, unchanged=U
//
// Usage:
//
//	unmask-admin review-crawler-list                # fetch JSON and diff
//	unmask-admin review-crawler-list -url file:...  # local compare
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
)

func cmdReviewCrawlerList(args []string) error {
	fs := flag.NewFlagSet("review-crawler-list", flag.ExitOnError)
	url := fs.String("url", crawlerListURL, "source URL")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout")
	_ = fs.Parse(args)

	// Parse the embedded copy.
	embedded, err := parseCrawlerList(assets.CrawlerUserAgentsJSON)
	if err != nil {
		return fmt.Errorf("parse embed: %w", err)
	}

	// Fetch upstream.
	cli := &http.Client{Timeout: *timeout}
	req, _ := http.NewRequest(http.MethodGet, *url, nil)
	req.Header.Set("User-Agent", "unmask-admin/"+Version)
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	upstreamRaw, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return err
	}
	upstream, err := parseCrawlerList(upstreamRaw)
	if err != nil {
		return fmt.Errorf("parse upstream: %w", err)
	}

	// diff
	added, removed, unchanged := diffPatternSets(embedded, upstream)

	fmt.Printf("== added (= patterns added upstream, %d) ==\n", len(added))
	for _, p := range added {
		fmt.Printf("  %s\n", p)
	}
	fmt.Printf("\n== removed (= patterns dropped upstream, %d) ==\n", len(removed))
	for _, p := range removed {
		fmt.Printf("  %s\n", p)
	}
	fmt.Printf("\n== summary ==\n")
	fmt.Fprintf(os.Stdout,
		"  embed: %d, upstream: %d, added=%d, removed=%d, unchanged=%d\n",
		len(embedded), len(upstream), len(added), len(removed), unchanged)
	return nil
}

// crawler-user-agents.json is an array of objects.  Extract only the pattern field.
type crawlerEntry struct {
	Pattern string `json:"pattern"`
}

func parseCrawlerList(b []byte) (map[string]bool, error) {
	var arr []crawlerEntry
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(arr))
	for _, e := range arr {
		if e.Pattern != "" {
			out[e.Pattern] = true
		}
	}
	return out, nil
}

func diffPatternSets(a, b map[string]bool) (added, removed []string, unchanged int) {
	for k := range b {
		if !a[k] {
			added = append(added, k)
		} else {
			unchanged++
		}
	}
	for k := range a {
		if !b[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}
