// unmask-admin: HTTP server + CLI sub-commands.
//
// usage:
//
//	unmask-admin serve          # start the HTTP server (FastAPI-style)
//	unmask-admin migrate        # create the schema
//	unmask-admin aggregate      # incremental aggregate (cron)
//	unmask-admin config-init    # emit a config.yml with a random secret
//	unmask-admin version
//
// Every sub-command can override the config with -config <path>.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	osuser "os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/feedserver"
	"github.com/unmask-sh/unmask/admin/internal/handlers"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/logwriter"
	"github.com/unmask-sh/unmask/admin/internal/mail"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/nginxlog"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/sharedfeed"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

const Version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "migrate":
		err = cmdMigrate(args)
	case "aggregate":
		err = cmdAggregate(args)
	case "config-init":
		err = cmdConfigInit(args)
	case "update-crawler-list":
		err = cmdUpdateCrawlerList(args)
	case "review-crawler-list":
		err = cmdReviewCrawlerList(args)
	case "render-nginx":
		err = cmdRenderNginx(args)
	case "events":
		err = cmdEvents(args)
	case "analyze":
		err = cmdAnalyze(args)
	case "user":
		err = cmdUser(args)
	case "doctor":
		err = cmdDoctor(args)
	case "install-ipgeo":
		err = cmdInstallIPGeo(args)
	case "feed-build":
		err = cmdFeedBuild(args)
	case "version", "-v", "--version":
		fmt.Println("unmask-admin", Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown sub-command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("%s: %v", cmd, err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `unmask-admin — JA4 bot challenge admin server

usage:
  unmask-admin serve [-config PATH]
  unmask-admin migrate [-config PATH]
  unmask-admin aggregate [-config PATH] [-days N]
  unmask-admin config-init [-out PATH]
  unmask-admin update-crawler-list [-out PATH]
  unmask-admin review-crawler-list [-url URL]
  unmask-admin render-nginx [-config PATH] [-out-dir DIR] [-dry-run]
  unmask-admin events [-config PATH] [-site SITE] [-phase PHASE] [-host HOST[,HOST]] [-since ID] [-poll-ms 1000]
  unmask-admin analyze [-config PATH] [-days 30] [-threshold 100] [-limit 20] [-site SITE]
  unmask-admin user list [-config PATH]
  unmask-admin user create <username> [-role superadmin|admin|viewer] [-password PASS]
  unmask-admin user reset-password <username> [-password PASS]
  unmask-admin user set-role <username> <role>
  unmask-admin user delete <username>
  unmask-admin doctor [-config PATH]
  unmask-admin install-ipgeo [-config PATH] [-path PATH] [-kind country|asn|all] [-quiet]
  unmask-admin feed-build [-config PATH] [-dry-run]
  unmask-admin version

env:
  UNMASK_CONFIG   default config path (overridden by -config)
`)
}

func loadSettings(configPath string) (settings.Settings, error) {
	return settings.Load(configPath)
}

// resolveHostID decides the name that uniquely identifies this host.
// Priority:
//  1. server.host_id in config.yml (explicit when hostnames collide on a shared DB)
//  2. os.Hostname() (usually sufficient; multi-host setups split automatically as long as the machine name differs)
//  3. "default" (last resort if both above are empty or hostname retrieval failed)
//
// Hostnames longer than 64 chars are truncated to fit the schema constraint (VARCHAR(64)).
// Control characters and whitespace cause migration / index issues, so apply a simple sanitize.
func resolveHostID(configured string) string {
	pick := strings.TrimSpace(configured)
	if pick == "" {
		if h, err := os.Hostname(); err == nil {
			pick = strings.TrimSpace(h)
		}
	}
	if pick == "" {
		pick = "default"
	}
	pick = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, pick)
	if len(pick) > 64 {
		pick = pick[:64]
	}
	return pick
}

// ----------------------------------------------------------------
// serve
// ----------------------------------------------------------------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	// Switch the log destination to our own file open (rather than systemd
	// StandardOutput=append:).  Needed so we can reopen the fd on SIGHUP for
	// logrotate compatibility.  On failure (permission etc.), fall back to
	// stderr and continue startup.
	var lw *logwriter.LogWriter
	if s.Server.LogPath != "" {
		w, err := logwriter.New(s.Server.LogPath)
		if err != nil {
			log.Printf("logwriter: %v (= stderr fallback)", err)
		} else {
			lw = w
			log.SetOutput(lw)
			log.Printf("logwriter: writing to %s (reopen on SIGHUP)", lw.Path())
		}
	}
	// Serve still starts even when DB connection fails (incomplete db: section
	// in admin.yml, or DB server not running).  The setup wizard at
	// /admin/setup/ accepts driver / connection info and hot-swaps it after
	// completion.  When conn == nil, the setup gate redirects every other URL.
	var conn *db.DB
	if c, err := db.Open(s.DB); err != nil {
		log.Printf("db: open failed (redirecting to setup wizard): %v", err)
	} else {
		conn = c
		defer conn.Close()
		// Run idempotent migrations at startup.  Even when a binary upgrade
		// requires a new column (old schema + new binary), event insert won't
		// break.  Serve continues on failure (don't disrupt existing
		// operations; a UI warning surfaces it even when setup is unfinished).
		if err := db.Migrate(conn); err != nil {
			log.Printf("db: migrate failed at startup (continuing with old schema; recommend running `unmask-admin migrate` manually): %v", err)
		}
	}

	// The initial admin user is now created via the **install wizard**
	// (/admin/setup/) — a unified design for "right after rpm/deb/apk
	// install / docker startup / manual install": user opens the admin UI in
	// a browser and the wizard appears (same flow as cacti / zabbix /
	// nextcloud).  Random password output to the log has been removed.
	//
	// CLI-oriented users can still bypass the wizard with
	// `unmask-admin user create <name> -role superadmin -password <pw>`.
	var userRepo *user.Repository
	if conn != nil {
		userRepo = user.New(conn)
	}

	gip := ipgeo.Open(s.IPGeo.MMDBPath, s.IPGeo.MMDBASNPath)
	defer gip.Close()
	if s.IPGeo.MMDBPath != "" {
		if gip.Loaded() {
			log.Printf("ipgeo: loaded %s", s.IPGeo.MMDBPath)
		} else {
			log.Printf("ipgeo: failed to load %s (country chart will not render)", s.IPGeo.MMDBPath)
		}
	}
	if s.IPGeo.MMDBASNPath != "" {
		if gip.ASNLoaded() {
			log.Printf("ipgeo-asn: loaded %s", s.IPGeo.MMDBASNPath)
		} else {
			log.Printf("ipgeo-asn: failed to load %s (popover will not show ASN)", s.IPGeo.MMDBASNPath)
		}
	}

	// Tail of nginx-only access_log + 1-minute flush goroutine + ban manager
	// only start when the DB is connected (setup complete).  Right after the
	// setup wizard finishes we expect a service restart to enable everything
	// (no hot-spawn, for simplicity).
	var nlog *nginxlog.Reader
	var banMgr *ban.Manager
	if conn != nil {
		// Enabled=false skips socket bind / recv loop (zero overhead).  The
		// flush loop still runs so buckets can be increased from inside via Bump.
		nlogSock := s.NginxLog.SocketPath
		if !s.NginxLog.Enabled {
			nlogSock = ""
		}
		nlog = nginxlog.Start(nlogSock, conn)
		defer nlog.Close()
		// Honeypot ban duration is per-site in v2; the ban manager is a
		// single shared writer so we seed it with the install-wide default.
		// Per-site BanDurationSec was considered and dropped: BAN list is
		// keyed on IP+JA4, not on the visited host.
		banDur := time.Duration(s.Nginx.Honeypot.ResolvedBanDurationSec()) * time.Second
		banMgr = ban.New(conn, s.Nginx.Honeypot.BanFilePath, banDur, s.Nginx.BypassIPs)
		banMgr.Start()
		defer banMgr.Close()
		nlog.SetHoneypotCallback(banMgr.Add)
		// crawler funnel: classify each access-log UA into AI/crawler buckets.
		nlog.SetCrawlerClassifier(classify.AICategory)
		// country breakdown for the 30-day chart: per-packet IP -> country
		// lookup, folded into unmask_traffic_country_hourly on the hour flush.
		nlog.SetIPGeo(gip)
	}

	// External webhook notifications (optional).  Safe no-op even when URL is empty.
	notifierInst := notifier.New(notifier.Config{
		Disabled:            s.Notifications.Disabled,
		URL:                 s.Notifications.URL,
		Format:              s.Notifications.Format,
		Sites:               s.Notifications.SiteLabel,
		BanEvents:           s.Notifications.BanEvents,
		ChallengeBurst:      s.Notifications.ChallengeBurst,
		BurstThresholdPer5m: s.Notifications.BurstThresholdPer5m,
	})
	// SMTP mailer (optional).  Empty Host -> no-op.  Used by alert mail / password reset.
	mailerInst := mail.New(mail.Config{
		Host:               s.SMTP.Host,
		Port:               s.SMTP.Port,
		Username:           s.SMTP.Username,
		Password:           s.SMTP.Password,
		FromAddress:        s.SMTP.FromAddress,
		FromName:           s.SMTP.FromName,
		StartTLS:           s.SMTP.StartTLS,
		InsecureSkipVerify: s.SMTP.InsecureSkipVerify,
	})
	// Wire mail notifications into the notifier.  The recipient resolver is a
	// thin closure that calls UserRepo.AlertRecipients.  On failure, return
	// an empty list to skip mail sending.
	notifierInst.WithMail(mailerInst, func() []string {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		xs, err := userRepo.AlertRecipients(ctx)
		if err != nil {
			log.Printf("alert recipients lookup: %v", err)
			return nil
		}
		return xs
	})
	if banMgr != nil {
		banMgr.OnCreated = notifierInst.BanCreated
	}

	hostID := resolveHostID(s.Server.HostID)
	log.Printf("host id: %s (recorded in the events.host column)", hostID)

	limiter := ratelimit.New()
	// GC stale entries (no hits in the last hour) every minute.  Prevents memory bloat.
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			limiter.Purge()
		}
	}()

	// Raw events are written via the batch flusher (N rows per single tx).
	// Started once at startup; settings save hot-reloads it; shutdown drains it.
	if conn != nil {
		events.StartFlusher(conn, s.EventsBatchSize, s.EventsBatchIntervalMs)
	}

	// classify init: apply the persisted per-pattern upstream disable filter
	// once at startup so the first request already sees the saved settings.
	classify.SetUpstreamDisabled(s.Nginx.SearchBots.UpstreamDisabled)

	// host inventory: apply the persisted disabled-host list so retired /
	// mis-configured instances are excluded from aggregation from the start.
	dashboard.SetDisabledHosts(s.Hosts.Disabled)

	h := &handlers.Handler{
		DB:          conn,
		Settings:    s,
		ConfigPath:  settings.ResolvePath(*configPath),
		Version:     Version,
		HostID:      hostID,
		IPGeo:       gip,
		NginxLog:    nlog,
		BanMgr:      banMgr,
		UserRepo:    userRepo,
		Notifier:    notifierInst,
		Mailer:      mailerInst,
		RateLimiter: limiter,
	}

	// Shared feed client: pass SettingsGetter / SettingsUpdate through Handler.
	// The Run() goroutine handles register + periodic pull only when submit or
	// subscribe is ON.  Without ConfigPath we can't persist, so don't build the
	// client at all (h.SharedFeed=nil also ignores the BAN button's share).
	if h.ConfigPath != "" {
		h.SharedFeed = &sharedfeed.Client{
			UserAgent:      "unmask-admin/" + Version,
			SettingsGetter: h.SnapshotSettings,
			SettingsUpdate: h.UpdateSettings,
		}
		go h.SharedFeed.Run(context.Background(), time.Hour)
	}

	// feed-server (hub mode).  Only Active() in the unmask.sh production.
	// Normal installs are no-op (ServeRegister / ServeSubmit handlers are not bound).
	var feedSrv *feedserver.Server
	if s.FeedServer.Active() {
		fs, err := feedserver.Open(s.FeedServer, nil)
		if err != nil {
			return fmt.Errorf("feedserver open: %w", err)
		}
		feedSrv = fs
		defer fs.Close()
		// BuildAndWrite + PruneExpired every hour.  Run once at startup as well.
		go func() {
			run := func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				if err := fs.BuildAndWrite(ctx); err != nil {
					log.Printf("feedserver build: %v", err)
				}
				if n, err := fs.PruneExpired(ctx); err != nil {
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
	}

	mux := buildRouter(s, h, feedSrv)

	// Prune old rows from unmask_event every 24h (those exceeding
	// h.Settings.EventsRetentionDays).  Aggregates (unmask_aggregate) are kept
	// permanently.  retention <= 0 -> no-op.  Run once at startup to sweep
	// backlog from immediately after install / restart.  Referring to
	// h.Settings inside the goroutine hot-picks up web UI saves.
	if conn != nil {
		go func() {
			runPrune := func() {
				retention := h.Settings.EventsRetentionDays
				if retention <= 0 {
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				n, err := events.PruneOldEvents(ctx, conn, retention)
				if err != nil {
					log.Printf("events prune: %v", err)
					return
				}
				if n > 0 {
					log.Printf("events prune: deleted %d row(s) older than %d days", n, retention)
				}
			}
			runPrune()
			t := time.NewTicker(24 * time.Hour)
			defer t.Stop()
			for range t.C {
				runPrune()
			}
		}()
	}

	// Roll new unmask_event rows into unmask_aggregate_hourly every 60s (plus a
	// startup pass).  The stats page reads those hourly rollups instead of
	// scanning the raw event table, which is ~10x slower under pure-Go SQLite.
	// PruneHourly trims buckets past the 32-day window roughly hourly.  Fully
	// in-process: no external cron required.
	if conn != nil {
		go func() {
			runAgg := func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				if err := dashboard.AggregateHourly(ctx, conn, gip); err != nil {
					log.Printf("hourly aggregate: %v", err)
				}
			}
			runPrune := func() {
				if err := dashboard.PruneHourly(context.Background(), conn); err != nil {
					log.Printf("hourly aggregate prune: %v", err)
				}
			}
			runAgg()
			runPrune()
			t := time.NewTicker(60 * time.Second)
			defer t.Stop()
			for tick := 0; ; tick++ {
				<-t.C
				runAgg()
				if tick%60 == 0 {
					runPrune()
				}
			}
		}()
	}

	listener, listenDesc, err := openListener(s.Server)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := &http.Server{
		Handler:           withAccessLog(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Treat SIGHUP as logrotate's "please reopen the log file" request
	// (don't stop the process).  SIGINT / SIGTERM trigger graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				if lw != nil {
					if err := lw.Reopen(); err != nil {
						log.Printf("logwriter: reopen failed: %v", err)
					} else {
						log.Printf("logwriter: reopened %s (via SIGHUP)", lw.Path())
					}
				}
				continue
			}
			log.Printf("shutdown signal received: %s", sig)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			// Drain the event flusher queue + perform a final flush.
			events.StopFlusher()
			return
		}
	}()

	log.Printf("unmask-admin %s listening on %s base=%s driver=%s",
		Version, listenDesc, s.Server.BasePath, conn.Driver)
	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// openListener listens on a unix domain socket when bind is "unix:/path",
// otherwise TCP "host:port".
//
// Extra steps for the unix case:
//   - If an existing file at that path is a socket, unlink it and re-listen
//     (cleans up leftovers from a dead prior process).  A regular file is an
//     error (avoids accidentally clobbering something).
//   - chmod (SocketMode, default 0660) to set permissions.
//   - chown (SocketGroup, default "nginx") to set group owner.  If the group
//     doesn't exist, log a warning and skip chown (keep chmod).
//
// The 2nd return is a descriptor for log display ("unix:/path" / "host:port").
func openListener(s settings.Server) (net.Listener, string, error) {
	if strings.HasPrefix(s.Bind, "unix:") {
		path := strings.TrimPrefix(s.Bind, "unix:")
		path = strings.TrimSpace(path)
		if path == "" {
			return nil, "", fmt.Errorf("unix socket path is empty (a path is required after `bind: unix:`)")
		}
		// stale socket cleanup.  If it's actually a socket file, unlink is safe.
		if fi, err := os.Lstat(path); err == nil {
			if fi.Mode()&os.ModeSocket != 0 {
				if err := os.Remove(path); err != nil {
					return nil, "", fmt.Errorf("remove stale socket %s: %w", path, err)
				}
			} else {
				return nil, "", fmt.Errorf("%s exists and is not a socket (refusing to overwrite another file; verify / remove manually)", path)
			}
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, "", err
		}
		// Permissions.  Default 0660 (owner rw + group rw).  Include group rw
		// so the nginx worker can read/write through group access.
		mode := parseFileMode(s.SocketMode, 0660)
		if err := os.Chmod(path, mode); err != nil {
			ln.Close()
			return nil, "", fmt.Errorf("chmod %s: %w", path, err)
		}
		// Group owner.  Default "nginx".  Warn only if the group doesn't exist.
		group := s.SocketGroup
		if group == "" {
			group = "nginx"
		}
		if g, err := osuser.LookupGroup(group); err == nil {
			gid, _ := strconv.Atoi(g.Gid)
			if err := os.Chown(path, -1, gid); err != nil {
				log.Printf("socket chown :%s failed: %v (insufficient permission?  socket stays at default uid)", group, err)
			}
		} else {
			log.Printf("socket group %q lookup failed: %v (chown skipped; the nginx worker may not be able to read it.  change SocketGroup or run groupadd)", group, err)
		}
		return ln, "unix:" + path, nil
	}

	// TCP path.
	addr := fmt.Sprintf("%s:%d", s.Bind, s.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}
	return ln, addr, nil
}

// parseFileMode interprets an octal string like "0660" as os.FileMode.  Empty
// or invalid returns the fallback.  Leading "0" is optional.
func parseFileMode(s string, fallback os.FileMode) os.FileMode {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		log.Printf("socket_mode %q parse failed (write in octal, e.g. 0660): %v.  fallback %#o", s, err, fallback)
		return fallback
	}
	return os.FileMode(v)
}

func buildRouter(s settings.Settings, h *handlers.Handler, feedSrv *feedserver.Server) *http.ServeMux {
	mux := http.NewServeMux()
	base := strings.TrimRight(s.Server.BasePath, "/")

	// Feed hub endpoints (bound only on unmask.sh when settings.FeedServer.Active()).
	// Public endpoints, no auth.  register is per-IP rate-limited; submit
	// uses Bearer token auth.  Not bound on normal installs.
	//
	// The paths are **not under** base_path (typically /unmask).  Clients
	// default to `https://unmask.sh/api/feed/{register,submit}`
	// (DefaultSharedFeed*URL in settings/SharedFeed).  base_path is reserved
	// for the admin UI.
	if feedSrv != nil {
		mux.HandleFunc("POST /api/feed/register", feedSrv.ServeRegister)
		mux.HandleFunc("POST /api/feed/submit", feedSrv.ServeSubmit)
	}

	// Go 1.22 enhanced ServeMux.  {site} is a per-site path param.  Literal
	// patterns are preferred as more specific, so the literal for the default
	// site and the {site} wildcard can coexist without routing ambiguity.

	// challenge HTML / JS.  Challenge endpoints accept **any** method so a
	// non-GET request that gets rewritten into here (= nginx `error_page 429
	// = @unmask_rate_challenge` rewrites POST /api/foo to /unmask/_rl/...
	// keeping the method) reaches the handler; ServeChallengeOrJSON then
	// returns an HTML challenge to browser navigation and a JSON 403 to
	// XHR / fetch clients.  Pre-v0.1, "GET " on the pattern made Go's
	// ServeMux respond 405 to anything else.
	mux.HandleFunc(base+"/challenge/{$}", h.ServeChallengeOrJSON)
	mux.HandleFunc(base+"/challenge/{site}/{$}", h.ServeChallengeOrJSON)
	// /static/challenge.js stays GET-only -- a real asset, not a challenge
	// response.  A POST to a static file legitimately deserves a 405.
	mux.HandleFunc("GET "+base+"/static/challenge.js", h.ServeChallengeJS)
	// Country-flag PNGs for the country chart (251 countries embedded).  ISO
	// 3166-1 alpha-2 + special (unknown).  No auth, same as challenge.js
	// (static images).
	mux.HandleFunc("GET "+base+"/static/flags/{name}", h.ServeFlag)
	// Pinned popover implementation shared by every admin page (click-pin /
	// drag / collapse / close).  Used to be inline-duplicated in
	// dashboard.html / hunt.html.  No auth.
	mux.HandleFunc("GET "+base+"/static/popover-pin.js", h.ServePopoverPinJS)
	mux.HandleFunc("GET "+base+"/static/popover-pin.css", h.ServePopoverPinCSS)
	mux.HandleFunc("GET "+base+"/static/icon.png", h.ServeIcon)
	// Branding logo (visitor-facing, no auth).  Single endpoint regardless
	// of the stored file's extension; the handler picks the correct
	// Content-Type from the on-disk file.  Cache-busting is via ?v=<mtime>
	// in the URL embedded in challenge.html / the admin preview thumbnail.
	mux.HandleFunc("GET "+base+"/branding/logo", h.ServeBrandingLogo)
	// Rate-limit path (nginx rewrites the original URI into /unmask/_rl<orig URI>).
	// Path subtree match (trailing slash, no {$}) catches any path after
	// _rl/.  Kept as a separate namespace to avoid collisions with
	// challenge/{site} routing.  Method-agnostic so a POST /api/foo that
	// trips `limit_req` and rewrites to /unmask/_rl/api/foo lands here.
	mux.HandleFunc(base+"/_rl/", h.ServeChallengeOrJSON)
	// legacy URL: /unmask/challenge.html -> same handler (redirect handled by nginx)
	mux.HandleFunc(base+"/challenge.html", h.ServeChallengeOrJSON)
	// debug / test pages (sanity checks).  Exposed via two paths:
	//   public side  /unmask/test/*       — gated by the settings.Challenge.PublicTestPages toggle (default 404)
	//   admin side   /unmask/admin/test/* — always available to logged-in users (AuthMiddleware)
	mux.HandleFunc("GET "+base+"/test/{$}", h.PublicTestGate(h.TestIndex))
	mux.HandleFunc("GET "+base+"/test/reset-cookie", h.PublicTestGate(h.ResetCookie))
	mux.HandleFunc("GET "+base+"/test/force-pow", h.PublicTestGate(h.ForcePoW))
	mux.HandleFunc("GET "+base+"/test/force-captcha", h.PublicTestGate(h.ForceCaptcha))
	mux.HandleFunc("GET "+base+"/test/force-pow-then-captcha", h.PublicTestGate(h.ForcePoWThenCaptcha))
	mux.HandleFunc("GET "+base+"/admin/test/{$}", h.AuthMiddleware(h.TestIndex))
	mux.HandleFunc("GET "+base+"/admin/test/reset-cookie", h.AuthMiddleware(h.ResetCookie))
	mux.HandleFunc("GET "+base+"/admin/test/force-pow", h.AuthMiddleware(h.ForcePoW))
	mux.HandleFunc("GET "+base+"/admin/test/force-captcha", h.AuthMiddleware(h.ForceCaptcha))
	mux.HandleFunc("GET "+base+"/admin/test/force-pow-then-captcha", h.AuthMiddleware(h.ForcePoWThenCaptcha))

	// API endpoints (default + per-site)
	mux.HandleFunc("POST "+base+"/api/verify", h.VerifyJSON)
	mux.HandleFunc("POST "+base+"/api/{site}/verify", h.VerifyJSON)
	mux.HandleFunc("GET "+base+"/api/captcha/new", h.CaptchaNew)
	mux.HandleFunc("GET "+base+"/api/{site}/captcha/new", h.CaptchaNew)
	mux.HandleFunc("POST "+base+"/api/debug", h.DebugBeacon)
	mux.HandleFunc("POST "+base+"/api/{site}/debug", h.DebugBeacon)

	// admin: login / logout are not behind session middleware (they're the
	// auth endpoints themselves), but IP allow_from is checked upfront to
	// prevent brute force from unauthorized IPs.
	// Wrapping every admin route in SetupGate redirects to /admin/setup/ when
	// setup is needed.  The setup endpoint itself needs no auth (there's no
	// user yet).
	mux.HandleFunc("GET "+base+"/admin/login", h.AdminIPAllowMiddleware(h.SetupGate(h.AdminLoginGet)))
	mux.HandleFunc("POST "+base+"/admin/login", h.AdminIPAllowMiddleware(h.SetupGate(h.AdminLoginPost)))
	// Password reminder (via mail).  Available only after the setup wizard completes (must pass the setup gate).
	mux.HandleFunc("GET "+base+"/admin/forgot-password", h.AdminIPAllowMiddleware(h.SetupGate(h.AdminForgotPasswordGet)))
	mux.HandleFunc("POST "+base+"/admin/forgot-password", h.AdminIPAllowMiddleware(h.SetupGate(h.AdminForgotPasswordPost)))
	mux.HandleFunc("GET "+base+"/admin/reset-password", h.AdminIPAllowMiddleware(h.SetupGate(h.AdminResetPasswordGet)))
	mux.HandleFunc("POST "+base+"/admin/reset-password", h.AdminIPAllowMiddleware(h.SetupGate(h.AdminResetPasswordPost)))
	mux.HandleFunc("GET "+base+"/admin/logout", h.AdminIPAllowMiddleware(h.AdminLogout))
	mux.HandleFunc("POST "+base+"/admin/logout", h.AdminIPAllowMiddleware(h.AdminLogout))
	// install wizard (cacti / zabbix style).  No auth required; once complete,
	// SetupGate redirects to /admin/ (prevents re-running setup).
	mux.HandleFunc("GET "+base+"/admin/setup/{$}", h.SetupGate(h.AdminSetupIndex))
	mux.HandleFunc("POST "+base+"/admin/setup/token", h.SetupGate(h.AdminSetupSaveToken))
	mux.HandleFunc("POST "+base+"/admin/setup/db", h.SetupGate(h.AdminSetupSaveDB))
	mux.HandleFunc("POST "+base+"/admin/setup/user", h.SetupGate(h.AdminSetupSaveUser))
	mux.HandleFunc("POST "+base+"/admin/setup/install", h.SetupGate(h.AdminSetupInstall))
	mux.HandleFunc("GET "+base+"/admin/setup/done", h.AdminSetupDone)
	// admin: /admin/ renders the top dashboard (summary).
	// /admin/stats/ shows the site list (or jumps straight to chart when site<=1).  /admin/stats/{site}/ shows per-site chart.
	mux.HandleFunc("GET "+base+"/admin/{$}",
		h.AuthMiddleware(h.AdminTopOverview))
	mux.HandleFunc("GET "+base+"/admin/stats/{$}",
		h.AuthMiddleware(h.AdminSiteList))
	mux.HandleFunc("GET "+base+"/admin/stats/{site}/{$}",
		h.AuthMiddleware(h.AdminDashboard))
	mux.HandleFunc("GET "+base+"/admin/api/funnel",
		h.AuthMiddleware(h.AdminFunnelJSON))
	mux.HandleFunc("GET "+base+"/admin/api/myip",
		h.AuthMiddleware(h.AdminMyIP))
	mux.HandleFunc("GET "+base+"/admin/api/events/stream",
		h.AuthMiddleware(h.AdminEventsStream))
	// one-click promotion of a ghost site into settings.Sites.Defined (admin or above)
	mux.HandleFunc("POST "+base+"/admin/api/sites/promote",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminSitePromote)))
	// disable / enable a host in the inventory (admin or above)
	mux.HandleFunc("POST "+base+"/admin/api/hosts/toggle",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminHostToggle)))

	// settings (web editing UI).  GET: viewer or above; POST: admin or above.
	mux.HandleFunc("GET "+base+"/admin/settings/{$}",
		h.AuthMiddleware(h.AdminSettingsIndex))
	mux.HandleFunc("POST "+base+"/admin/settings/save",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminSettingsSave)))
	// per-site card endpoints for the Branding / Challenge tabs (= v2
	// scalar override surface).  Each writes one Sites[<host>] entry.
	mux.HandleFunc("POST "+base+"/admin/settings/branding/site/save",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminBrandingSiteSave)))
	mux.HandleFunc("POST "+base+"/admin/settings/branding/site/delete",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminBrandingSiteDelete)))
	mux.HandleFunc("POST "+base+"/admin/settings/challenge/site/save",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminChallengeSiteSave)))
	mux.HandleFunc("POST "+base+"/admin/settings/challenge/site/delete",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminChallengeSiteDelete)))
	// rate_limit / honeypot scalar wrappers (= v2 phase 2).  Same shape:
	// one Sites[<host>] entry per save / delete.  The list-style tabs
	// (= bypass_paths / protected_paths / honeypot URLs) parse all rows
	// in the main settings save, so they have no /site/ endpoint of their
	// own.
	// rate_limit per-site scalar routes (= site/save, site/delete) were
	// dropped in v2 step b: per-site rate variation now lives in RateZone
	// rows with a Site column instead of a per-host scalar wrapper.
	// webhook test send (notifications tab's "send test" button)
	mux.HandleFunc("POST "+base+"/admin/api/notify/test",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminNotifyTest)))
	mux.HandleFunc("POST "+base+"/admin/api/smtp/test",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminSMTPTest)))
	// 1-click DB-IP Lite install / refresh.  Calls the same library as
	// `unmask-admin install-ipgeo` and reloads the in-process ipgeo Reader.
	// Accepts ?kind=country (default) or ?kind=asn.
	mux.HandleFunc("POST "+base+"/admin/api/ipgeo/install",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminIPGeoInstall)))

	// JA4 playground (visualize "what would happen if I entered this JA4 + UA?")
	mux.HandleFunc("GET "+base+"/admin/playground/{$}",
		h.AuthMiddleware(h.AdminPlayground))
	mux.HandleFunc("POST "+base+"/admin/api/playground/eval",
		h.AuthMiddleware(h.AdminPlaygroundEval))

	// forward-auth mode endpoint (called by all of nginx auth_request /
	// Apache forward-auth / Caddy forward_auth / Envoy ext_authz).
	// No auth (the HTTP server's subrequest).  Supports both GET / POST.
	mux.HandleFunc("GET "+base+"/api/check", h.AuthCheck)
	mux.HandleFunc("POST "+base+"/api/check", h.AuthCheck)
	mux.HandleFunc("GET "+base+"/api/{site}/check", h.AuthCheck)
	mux.HandleFunc("POST "+base+"/api/{site}/check", h.AuthCheck)

	// users management tab (superadmin only)
	mux.HandleFunc("GET "+base+"/admin/users/{$}",
		h.AuthMiddleware(h.RequireRole(user.RoleSuperadmin, h.AdminUsersIndex)))
	mux.HandleFunc("GET "+base+"/admin/users/new",
		h.AuthMiddleware(h.RequireRole(user.RoleSuperadmin, h.AdminUsersNew)))
	mux.HandleFunc("GET "+base+"/admin/users/{id}/edit",
		h.AuthMiddleware(h.RequireRole(user.RoleSuperadmin, h.AdminUsersEdit)))
	mux.HandleFunc("POST "+base+"/admin/users/save",
		h.AuthMiddleware(h.RequireRole(user.RoleSuperadmin, h.AdminUsersSave)))

	// persistent BAN tab (admin or above)
	mux.HandleFunc("GET "+base+"/admin/bans/{$}",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminBansIndex)))
	mux.HandleFunc("POST "+base+"/admin/bans/save",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminBansSave)))

	// bot hunt tab (admin or above)
	mux.HandleFunc("GET "+base+"/admin/hunt/{$}",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminHuntIndex)))
	mux.HandleFunc("POST "+base+"/admin/hunt/action",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminHuntAction)))

	// audit log viewer tab (admin or above)
	mux.HandleFunc("GET "+base+"/admin/audit/{$}",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminAuditIndex)))
	// audit rollback: re-applies a captured `before` snapshot.  Restricted
	// to superadmin since it overwrites the live config.
	mux.HandleFunc("POST "+base+"/admin/audit/restore",
		h.AuthMiddleware(h.RequireRole(user.RoleSuperadmin, h.AdminAuditRestore)))
	// Explicit snapshot capture (no mutation).  admin or above.
	mux.HandleFunc("POST "+base+"/admin/settings/snapshot",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminSettingsSnapshot)))
	// Export current settings as yaml file.  admin or above.
	mux.HandleFunc("GET "+base+"/admin/settings/export",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminSettingsExport)))

	// Change own password (available to every role; current password required).
	mux.HandleFunc("GET "+base+"/admin/profile/{$}",
		h.AuthMiddleware(h.AdminProfileIndex))
	mux.HandleFunc("POST "+base+"/admin/profile/save",
		h.AuthMiddleware(h.AdminProfileSave))

	// docs consolidated at unmask.sh/docs/ (in-admin docs would be duplicate maintenance, so removed).
	// Redirect legacy /admin/docs/ /admin/install/ traffic to external docs with 302.
	docsRedirect := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://unmask.sh/docs/", http.StatusFound)
	}
	mux.HandleFunc("GET "+base+"/admin/docs/{$}", h.AuthMiddleware(docsRedirect))
	mux.HandleFunc("GET "+base+"/admin/install/{$}", h.AuthMiddleware(docsRedirect))

	// health
	mux.HandleFunc("GET "+base+"/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})

	// metrics (Prometheus text format).  bind=127.0.0.1 by default, so the
	// scraper (prometheus exporter / agent) typically reads from loopback.
	mux.HandleFunc("GET "+base+"/metrics", h.Metrics)

	return mux
}

func withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.code, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) {
	s.code = c
	s.ResponseWriter.WriteHeader(c)
}

// Flush forwards the http.Flusher needed by streaming handlers such as SSE.
// No-op when the underlying ResponseWriter does not implement Flusher.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ----------------------------------------------------------------
// migrate
// ----------------------------------------------------------------

func cmdMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		return err
	}
	fmt.Println("schema applied")
	// ID-based linking: backfill ja4_verdict_id for existing rows via name lookup.
	// Build the preset registry from built-in + settings.Extra.
	extras := make([]nginxconf.ExtraVerdict, 0, len(s.Nginx.JA4Verdicts.Extra))
	for _, e := range s.Nginx.JA4Verdicts.Extra {
		extras = append(extras, nginxconf.ExtraVerdict{
			ID: e.ID, Verdict: e.Verdict, Action: e.Action, Pattern: e.Pattern,
		})
	}
	reg := nginxconf.BuildVerdictRegistry(extras)
	nameToID := reg.AllNameToID()
	if n, err := db.BackfillVerdictIDs(conn, nameToID); err != nil {
		return fmt.Errorf("backfill verdict id: %w", err)
	} else if n > 0 {
		fmt.Printf("backfilled ja4_verdict_id for %d row(s)\n", n)
	}
	return nil
}

// ----------------------------------------------------------------
// aggregate (for cron; currently writes daily aggregates from the event table into unmask_aggregate)
// ----------------------------------------------------------------

func cmdAggregate(args []string) error {
	fs := flag.NewFlagSet("aggregate", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	days := fs.Int("days", 30, "how many days back to (re)aggregate")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()

	since := conn.NowMinusMinutes(*days * 24 * 60)
	stmt := fmt.Sprintf(`
        SELECT DATE(date_created), 'phase', phase, COUNT(*)
        FROM unmask_event
        WHERE date_created > %s
        GROUP BY DATE(date_created), phase
    `, since)
	rows, err := conn.Query(stmt)
	if err != nil {
		return err
	}
	defer rows.Close()

	upsert := `INSERT INTO unmask_aggregate (bucket_date, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, ?)`
	if conn.Driver == db.DriverSQLite {
		upsert += ` ON CONFLICT(bucket_date, bucket_kind, bucket_key) DO UPDATE SET cnt = excluded.cnt`
	} else {
		upsert += ` ON DUPLICATE KEY UPDATE cnt = VALUES(cnt)`
	}

	n := 0
	for rows.Next() {
		var dateRaw any
		var kind, key string
		var cnt int
		if err := rows.Scan(&dateRaw, &kind, &key, &cnt); err != nil {
			return err
		}
		var dateStr string
		switch v := dateRaw.(type) {
		case string:
			dateStr = v
		case []byte:
			dateStr = string(v)
		case time.Time:
			dateStr = v.Format("2006-01-02")
		default:
			dateStr = fmt.Sprintf("%v", v)
		}
		if _, err := conn.Exec(upsert, dateStr, kind, key, cnt); err != nil {
			return err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	fmt.Printf("aggregate: wrote %d phase rows (last %d days)\n", n, *days)

	// serve-by-kind + per-day totals: feeds the dashboard 30-day chart 2.
	// Pre-aggregating here keeps that chart off the slow live event-table
	// scan it used to run on every dashboard page load.
	if err := dashboard.AggregateServeKind(context.Background(), conn, s.Nginx, *days); err != nil {
		return fmt.Errorf("aggregate serve-kind: %w", err)
	}
	fmt.Printf("aggregate: wrote serve-kind rows (last %d days)\n", *days)
	return nil
}

// ----------------------------------------------------------------
// events (tail -f style streaming of unmask_event; exit on SIGINT)
// ----------------------------------------------------------------

func cmdEvents(args []string) error {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	site := fs.String("site", "", "filter by site id (empty = all sites)")
	phase := fs.String("phase", "", "filter by phase (load / pow / verify_ok / etc.)")
	host := fs.String("host", "", "filter by host id (comma-separated for multiple; empty = all hosts)")
	since := fs.Int64("since", -1, "start id (-1 = from MAX(id) onward; 0 = everything)")
	pollMs := fs.Int("poll-ms", 1000, "polling interval in ms")
	_ = fs.Parse(args)
	var hosts []string
	if h := strings.TrimSpace(*host); h != "" {
		hosts = strings.Split(h, ",")
	}

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	sinceID := *since
	if sinceID < 0 {
		mx, err := events.MaxID(ctx, conn)
		if err != nil {
			return err
		}
		sinceID = mx
		fmt.Fprintf(os.Stderr, "tailing unmask_event from id=%d (tail)\n", sinceID)
	}

	pollDur := time.Duration(*pollMs) * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "stopped")
			return nil
		default:
		}
		rows, err := events.FetchSince(ctx, conn, sinceID, *site, *phase, hosts, 200)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			fmt.Fprintf(os.Stderr, "fetch error: %v\n", err)
			time.Sleep(pollDur)
			continue
		}
		for _, r := range rows {
			fmt.Printf("[%d] %s %-9s host=%-12s site=%-8s ip=%-15s ja4=%s verdict=%s flags=%d ua=%q\n",
				r.ID, r.Date, r.Phase, r.Host, r.Site, r.IP, r.JA4, r.Verdict, r.Flags, truncForCLI(r.UA, 60))
			if r.ID > sinceID {
				sinceID = r.ID
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pollDur):
		}
	}
}

func truncForCLI(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ----------------------------------------------------------------
// config-init
// ----------------------------------------------------------------

func cmdConfigInit(args []string) error {
	fs := flag.NewFlagSet("config-init", flag.ExitOnError)
	out := fs.String("out", "-", "output path (- = stdout)")
	_ = fs.Parse(args)

	bv := randHex(24)
	cb := randHex(24)
	body := fmt.Sprintf(`# unmask config (generated by unmask-admin config-init)
db:
  driver: sqlite
  sqlite_path: /var/lib/unmask/unmask.sqlite
  # mariadb:
  #   host: 127.0.0.1
  #   port: 3306
  #   user: unmask
  #   password: ""
  #   database: unmask

secret:
  # _bv cookie HMAC-SHA1 key.  If leaked, change this and re-sync nginx's secret.conf.
  bv_secret: %q
  # math captcha token HMAC-SHA256 base
  captcha_secret_base: %q

challenge:
  cookie_days: 3
  debug_rate_limit_per_5min: 20
  challenge_html_path: ""   # empty -> use the embedded version inside the binary
  captcha:
    provider: builtin
    builtin_score_threshold: 0.5   # behavioral pass threshold (builtin only)

server:
  bind: 127.0.0.1
  port: 9477
  base_path: /unmask

# Authentication is the internal user DB.  At first start, an admin/superadmin
# is auto-created and the random password is shown in the log exactly once.
# CLI management: unmask-admin user create / reset-password / set-role / delete
`, bv, cb)

	if *out == "-" {
		fmt.Print(body)
		return nil
	}
	return os.WriteFile(*out, []byte(body), 0o600)
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

// (bootstrapInitialAdmin was removed in v0.1.  Admin creation is now
// unified to either the install wizard or the CLI sub-command
// `unmask-admin user create`.)
