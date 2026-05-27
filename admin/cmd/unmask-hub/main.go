// unmask-hub — Unmask Community Bans hub server (= unmask.sh side only).
//
// Operator-side installs never link this binary; the admin daemon ships
// without the hub code so the surface area of a typical install stays
// small.  Builds + ships as a separate binary so unmask.sh can run it
// next to (or instead of) unmask-admin without dragging hub deps into
// every install.
//
// Reads feed_server.* from /etc/unmask/config.yml (= same yaml shape as
// the admin's settings.FeedServer block) so the existing unmask.sh
// install only has to swap which systemd unit binds the /api/feed/*
// endpoints.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/feedserver"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Version is set via -ldflags at build time.  Mirrors unmask-admin's
// release-versioning scheme so both binaries report the same tag.
var Version = "dev"

const usage = `unmask-hub — Unmask Community Bans hub server (= unmask.sh side)

usage:
  unmask-hub serve [-config PATH] [-addr ADDR]
  unmask-hub build [-config PATH] [-dry-run]
  unmask-hub version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "build":
		err = cmdBuild(args)
	case "version", "--version", "-v":
		fmt.Println(Version)
		return
	case "help", "--help", "-h":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown sub-command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml (= reads feed_server.*)")
	addr := fs.String("addr", "127.0.0.1:8766", "HTTP listen address")
	_ = fs.Parse(args)

	s, err := settings.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", *configPath, err)
	}
	if !s.FeedServer.Active() {
		return fmt.Errorf("feed_server is not active; set feed_server.enabled=true + db_path in config.yml")
	}
	srv, err := feedserver.Open(s.FeedServer, nil)
	if err != nil {
		return fmt.Errorf("feedserver open: %w", err)
	}
	defer srv.Close()

	// Hourly build + prune, with a kick at startup so the JSON dump is
	// fresh the moment the new binary takes over from the admin one.
	go func() {
		run := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := srv.BuildAndWrite(ctx); err != nil {
				log.Printf("feedserver build: %v", err)
			}
			if n, err := srv.PruneExpired(ctx); err != nil {
				log.Printf("feedserver prune: %v", err)
			} else if n > 0 {
				log.Printf("feedserver: pruned %d expired submissions", n)
			}
		}
		run()
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			run()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/feed/register", srv.ServeRegister)
	mux.HandleFunc("POST /api/feed/submit", srv.ServeSubmit)
	mux.HandleFunc("GET /api/feed/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		log.Printf("unmask-hub serving %s", *addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()
	<-sigCh
	log.Printf("unmask-hub: shutdown signal, draining")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	return nil
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	dryRun := fs.Bool("dry-run", false, "write to stdout instead of file")
	_ = fs.Parse(args)

	s, err := settings.Load(*configPath)
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
		fmt.Fprintf(os.Stderr, "build: pruned %d expired submission(s)\n", n)
	}
	return nil
}
