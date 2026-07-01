// update-iprange: refresh the bypass-IP snapshot (Googlebot / Bingbot / GPTBot
// etc. official ranges) from the unmask.sh hub-aggregated document.
//
// Run at release time against the embed source so a fresh install ships
// current ranges instead of a months-old build snapshot:
//
//	unmask update-iprange -out admin/assets/iprange   # refresh the embed source
//	# then rebuild -- the JSONs are compiled in via //go:embed iprange/*.json
//	git add admin/assets/iprange && git commit
//
// With no -out it writes the runtime override dir (= a one-shot manual sync,
// equivalent to one tick of the daemon's background goroutine).  Best-effort:
// on a fetch error nothing is written and the previous files stay in place.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

func cmdUpdateIPRange(args []string) error {
	fs := flag.NewFlagSet("update-iprange", flag.ExitOnError)
	out := fs.String("out", nginxconf.SyncDefaultDir,
		"output dir for the per-vendor JSONs (= pass admin/assets/iprange to refresh the embed source)")
	url := fs.String("url", nginxconf.SyncDefaultHubURL, "hub aggregated-doc URL")
	timeout := fs.Duration("timeout", 60*time.Second, "HTTP timeout")
	_ = fs.Parse(args)

	s := nginxconf.NewSync()
	s.Dir = *out
	s.HubURL = *url
	s.UserAgent = "unmask/" + Version
	s.HTTPClient = &http.Client{Timeout: *timeout}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+5*time.Second)
	defer cancel()
	if err := s.PullOnce(ctx); err != nil {
		return fmt.Errorf("refresh from %s: %w", *url, err)
	}
	// Drop the If-Modified-Since marker PullOnce leaves behind.  It is not
	// embedded (go:embed is iprange/*.json) but keeps the embed tree clean.
	_ = os.Remove(filepath.Join(*out, ".last-modified"))

	entries, _ := filepath.Glob(filepath.Join(*out, "*.json"))
	fmt.Fprintf(os.Stderr, "refreshed %d vendor iprange file(s) in %s\n", len(entries), *out)
	for _, e := range entries {
		if fi, err := os.Stat(e); err == nil {
			fmt.Fprintf(os.Stderr, "  %s (%d bytes)\n", filepath.Base(e), fi.Size())
		}
	}
	return nil
}
