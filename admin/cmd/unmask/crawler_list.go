// update-crawler-list: fetch the latest JSON from monperrus/crawler-user-agents.
//
// Updating the embedded crawler-user-agents.json requires a binary rebuild, but the
// admin side can prefer an external path via the UNMASK_CRAWLER_UA_JSON env var
// (= consulted by the classify package).
//
// Usage:
//
//	unmask update-crawler-list -out /etc/unmask/crawler-user-agents.json
//	systemctl restart unmask   # to refresh the cache
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

const crawlerListURL = "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json"

func cmdUpdateCrawlerList(args []string) error {
	fs := flag.NewFlagSet("update-crawler-list", flag.ExitOnError)
	out := fs.String("out", "-", "output path (- = stdout)")
	url := fs.String("url", crawlerListURL, "source URL")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout")
	_ = fs.Parse(args)

	cli := outbound.Client(*timeout)
	req, _ := http.NewRequest(http.MethodGet, *url, nil)
	req.Header.Set("User-Agent", "unmask/"+Version)
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return err
	}
	if len(body) < 1024 {
		return fmt.Errorf("response too small (%d bytes), aborting", len(body))
	}
	// What is written is what the daemon will build its rescue lists from:
	// a body that is not the list -- an error page answered with 200, a
	// download cut short -- is refused here and the file is left as it was.
	if n, err := assets.CrawlerUAEntries(body); err != nil {
		return fmt.Errorf("the response is not a crawler list (%v), aborting", err)
	} else if n < assets.MinCrawlerUAEntries {
		return fmt.Errorf("the response holds %d entries with a pattern, fewer than the %d a crawler list has, aborting", n, assets.MinCrawlerUAEntries)
	}

	if *out == "-" {
		os.Stdout.Write(body)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	// Beside the target and renamed over it: a daemon starting while this
	// runs reads the old list or the new one, never the first half of one.
	tmp := *out + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, *out); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(body), *out)
	return nil
}
