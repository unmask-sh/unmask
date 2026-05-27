// feed-build: cron entry that runs the community-bans aggregation + feed.json
// generation exactly once.
//
//	unmask-admin feed-build                # run with feed_server settings from config.yml
//	unmask-admin feed-build -dry-run       # print JSON to stdout only (= no file update)
//
// admin serve runs this automatically every hour, so this command is intended for:
//   - running on the exact cron tick
//   - refreshing feed.json immediately after a settings change
//
// No-op when Active() is false (= Enabled=false / DBPath empty).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/feedserver"
)

func cmdFeedBuild(args []string) error {
	fs := flag.NewFlagSet("feed-build", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	dryRun := fs.Bool("dry-run", false, "write to stdout instead of file")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	if !s.FeedServer.Active() {
		fmt.Fprintln(os.Stderr, "feed_server.enabled=false / db_path=empty — nothing to do")
		return nil
	}

	srv, err := feedserver.Open(s.FeedServer, nil)
	if err != nil {
		return err
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if *dryRun {
		doc, err := srv.Build(ctx)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	}

	if err := srv.BuildAndWrite(ctx); err != nil {
		return err
	}
	if n, err := srv.PruneExpired(ctx); err != nil {
		return err
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "feed-build: pruned %d expired submission(s)\n", n)
	}
	return nil
}
