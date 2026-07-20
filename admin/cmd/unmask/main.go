// unmask: HTTP server + CLI sub-commands.
//
// usage:
//
//	unmask serve          # start the HTTP server (FastAPI-style)
//	unmask migrate        # create the schema
//	unmask config-init    # emit a config.yml with a random secret
//	unmask version
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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/communitybans"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/handlers"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/mail"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/nginxlog"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"github.com/unmask-sh/unmask/admin/internal/privacypass"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/safe"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
	"github.com/unmask-sh/unmask/admin/internal/webbotauth"
)

// Version is the build version.  A var (not const) so the release build can
// inject it: `go build -ldflags "-X main.Version=$(UNMASK_VERSION)"` (the
// Makefile does this).  A const would silently ignore the -X flag, leaving
// `unmask version` and the startup log stuck at the default forever.
var Version = "0.1.6"

func main() {
	// Resolve the init-system-specific restart command once, so every UI string
	// that tells the operator to restart unmask shows the command that actually
	// works on this host (systemd vs OpenRC).  Cheap (a couple of stats); done
	// for all subcommands so CLI help paths stay consistent too.
	i18n.RestartCmd = detectRestartCommand()

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
	case "config-init":
		err = cmdConfigInit(args)
	case "update-crawler-list":
		err = cmdUpdateCrawlerList(args)
	case "review-crawler-list":
		err = cmdReviewCrawlerList(args)
	case "update-iprange":
		err = cmdUpdateIPRange(args)
	case "render-nginx":
		err = cmdRenderNginx(args)
	case "events":
		err = cmdEvents(args)
	case "analyze":
		err = cmdAnalyze(args)
	case "db-analyze":
		err = cmdDBAnalyze(args)
	case "user":
		err = cmdUser(args)
	case "doctor":
		err = cmdDoctor(args)
	case "install-ipgeo":
		err = cmdInstallIPGeo(args)
	case "version", "-v", "--version":
		fmt.Println("unmask", Version)
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
	fmt.Fprint(os.Stderr, `unmask — JA4 bot challenge admin server

usage:
  unmask serve [-config PATH]
  unmask migrate [-config PATH]
  unmask config-init [-out PATH]
  unmask update-crawler-list [-out PATH]
  unmask review-crawler-list [-url URL]
  unmask update-iprange [-out DIR] [-url URL]
  unmask render-nginx [-config PATH] [-out-dir DIR] [-dry-run]
  unmask events [-config PATH] [-site SITE] [-phase PHASE] [-host HOST[,HOST]] [-since ID] [-poll-ms 1000]
  unmask analyze [-config PATH] [-days 30] [-threshold 100] [-limit 20] [-site SITE]
  unmask db-analyze [-config PATH] [-timeout 10m]
  unmask user list [-config PATH]
  unmask user create <username> [-role superadmin|admin|viewer] [-password PASS]
  unmask user reset-password <username> [-password PASS]
  unmask user set-role <username> <role>
  unmask user delete <username>
  unmask doctor [-config PATH]
  unmask install-ipgeo [-config PATH] [-path PATH] [-kind country|asn|all] [-quiet]
  unmask version

note: the hub-server commands (= /api/feed/* on unmask.sh) moved to a
separate binary "unmask-hub" so operator-side installs no longer carry
the hub code.

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

// detectRestartCommand returns the bare shell command that restarts the unmask
// service under the init system this host is actually running.  The admin
// binary ships identically to every distro (rpm/deb/apk), so the correct form
// — `systemctl restart unmask` (systemd) vs `rc-service unmask restart`
// (OpenRC/Alpine) — is only knowable at runtime.  Detection mirrors
// sd_booted(3): /run/systemd/system exists iff the host booted under systemd,
// and /run/openrc exists under OpenRC.
//
// When neither is found there is no service manager to name (a container whose
// PID 1 is unmask itself, or an unsupported init), so it returns "".  The UI
// then keeps its plain-words "restart unmask" and prints NO command, rather than
// guessing `systemctl ...` on a host where systemctl may not exist.
func detectRestartCommand() string {
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return "systemctl restart unmask"
	}
	if fi, err := os.Stat("/run/openrc"); err == nil && fi.IsDir() {
		return "rc-service unmask restart"
	}
	// OpenRC may not have populated /run/openrc yet (early boot) but always
	// ships the /sbin/openrc binary; treat its presence as OpenRC too.
	if _, err := os.Stat("/sbin/openrc"); err == nil {
		return "rc-service unmask restart"
	}
	return ""
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	// Point the setup-token file at the resolved config's directory, so a
	// relocated install or a second instance reads its OWN .setup-token rather
	// than the hard-coded /etc/unmask one.  Package installs (config in
	// /etc/unmask) are unaffected.
	if resolved := settings.ResolvePath(*configPath); resolved != "" {
		handlers.SetSetupTokenDir(filepath.Dir(resolved))
	}

	// Startup self-check: a rendered http.inc whose bv_secret no longer matches
	// the running config means the operator re-keyed or re-rendered but skipped
	// the nginx RESTART the native module needs — every _bv the daemon issues is
	// then rejected and visitors loop on the challenge.  This went unnoticed for
	// hours on 2026-06-08, so surface it loudly at startup; a deploy that forgot
	// the restart is then obvious in the journal.  No-op in forward-auth mode
	// (no rendered http.inc) and on a fresh install.
	if nginxconf.BVSecretDesynced(s.Nginx.OutputDir, s.Secret.BVSecret) {
		log.Printf("unmask: WARNING: bv_secret desync — rendered http.inc differs from the running config; the native plugin rejects every _bv and loops visitors on the challenge. Run `unmask render-nginx` and RESTART nginx (a reload won't reload the module). See the 2026-06-08 incident.")
	}

	// Probe the host nginx once so Render picks the rate composition flow: nginx
	// >= 1.17.6 → compose (a deny zone wins over a protected-path challenge),
	// older → classic (limit_req_dry_run / the limit_req_status field would fail).
	// Cached process-wide; Render never execs nginx itself (it runs on the
	// settings-save path).  nginx.rate_compose_mode overrides; "auto" (default)
	// uses this probe, resolving to classic when nginx isn't detectable (safe
	// everywhere).  DiagnoseComposeMode classifies the result for the operator.
	dryOK, ngxVer, ngxDetected := nginxconf.DetectDryRunSupport()
	if ngxDetected {
		nginxconf.SetDryRunSupported(dryOK)
	}
	if diag := nginxconf.DiagnoseComposeMode(s, ngxVer, ngxDetected, dryOK); diag.Level != nginxconf.ComposeDiagOK {
		// Tag by severity: an Error-level diagnosis (config that cannot enforce /
		// reload) must be greppable as ERROR, not blend in as one more warning.
		tag := "WARNING"
		if diag.Level == nginxconf.ComposeDiagError {
			tag = "ERROR"
		}
		log.Printf("unmask: %s: %s", tag, diag.Message)
	}

	// Logging follows 12-factor: every log line goes to stderr and the init
	// system (= systemd journald / OpenRC syslog / docker container runtime)
	// handles routing + retention.  No app-side file rotation; see
	// https://12factor.net/logs.
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
			log.Printf("db: migrate failed at startup (continuing with old schema; recommend running `unmask migrate` manually): %v", err)
		}
	}

	// The initial admin user is now created via the **install wizard**
	// (/admin/setup/) — a unified design for "right after rpm/deb/apk
	// install / docker startup / manual install": user opens the admin UI in
	// a browser and the wizard appears (same flow as cacti / zabbix /
	// nextcloud).  Random password output to the log has been removed.
	//
	// CLI-oriented users can still bypass the wizard with
	// `unmask user create <name> -role superadmin -password <pw>`.
	var userRepo *user.Repository
	if conn != nil {
		userRepo = user.New(conn)
	}

	// setupComplete reports whether the install wizard has been finished — i.e.
	// an admin user exists.  First contact with the hub (community-bans register
	// / pull) and the managed-mmdb auto-fetch are gated on it so a fresh box does
	// NOT phone home before the operator has opened the wizard and consented: the
	// README frames Community Bans as opt-in, and an air-gapped box would
	// otherwise log alarming register / fetch failures before setup even starts.
	// The wizard's post-completion auto re-exec re-evaluates this, so the first
	// pull fires right after setup is done.
	setupComplete := false
	if userRepo != nil {
		if n, err := userRepo.Count(context.Background()); err == nil && n > 0 {
			setupComplete = true
		}
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
	// First-run: pull a missing managed DB-IP Lite mmdb in the background (from
	// the unmask.sh mirror, CC BY 4.0) so geo features come up without a manual
	// install-ipgeo, whatever the install method was.  Reloads gip on success.
	// Gated on setupComplete so a pre-wizard / air-gapped box doesn't reach out
	// to the mirror (and log a fetch failure) before the operator consents.
	if s.IPGeo.AutoFetch && setupComplete {
		ipgeo.AutoFetchMissing(s.IPGeo.MMDBPath, s.IPGeo.MMDBASNPath, gip)
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
		banMgr = ban.New(conn, s.Nginx.Honeypot.BanFilePath, banDur)
		// Seed the per-source action resolver from the BOOT settings *before*
		// Start(), because Start() writes the ban file immediately (initial
		// flush) and flush() resolves every row whose action column is empty
		// through EffectiveAction.  With no resolver installed that falls back
		// to "deny", so every restart used to rewrite honeypot/manual bans as a
		// hard deny -- ignoring the operator's configured captcha_only /
		// pow_then_captcha until some later add re-flushed the file.  The live
		// resolver (below, once the Handler exists) replaces this one so
		// settings changes still apply without a restart.
		bootSettings := s
		banMgr.SetActionResolver(func(source string) string {
			return bootSettings.Nginx.Bans.ResolveAction(source, bootSettings.Nginx.Honeypot.DefaultAction)
		})
		banMgr.Start()
		defer banMgr.Close()
		// Native-mode honeypot ban: SetHoneypotCallback is registered AFTER the
		// Handler is built (see below, in the `if banMgr != nil` block), because
		// it resolves the trap's per-preset action via h.SnapshotSettings (live
		// settings) and h does not exist yet here.
		// Never honeypot-ban a rescued search/AI crawler (= CLAUDE.md #4; mirrors
		// the forward-auth search-bot veto-pass on the access-log ban path).
		nlog.SetSearchBotCheck(func(ua string) bool {
			return classify.IsBot(ua, "").String() == "search_ai"
		})
		// crawler funnel: classify each access-log UA into AI/crawler buckets.
		nlog.SetCrawlerClassifier(classify.LookupTag)
		// crawler drill-down: resolve the individual crawler within its category
		// (Googlebot, Bingbot, ...), folded into unmask_crawler_detail_hourly.
		nlog.SetCrawlerNamer(classify.LookupCrawlerIn)
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
			safe.Run("limiter-purge", limiter.Purge)
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
	// Publish the initial settings snapshot.  settingsPtr is unexported, so the
	// daemon seeds it through the exported setter rather than a struct literal.
	h.SetSettings(s)

	// Wire the ban file's per-source action resolver to live settings so a
	// honeypot/manual/community_bans knob change picks up on the next 60s flush
	// without restarting the admin (= h.SnapshotSettings reads the latest
	// in-memory copy after any AdminSettingsSave).
	if banMgr != nil {
		banMgr.SetActionResolver(func(source string) string {
			cur := h.SnapshotSettings()
			return cur.Nginx.Bans.ResolveAction(source, cur.Nginx.Honeypot.DefaultAction)
		})
		// Bypass allowlist for the honeypot auto-ban + manual BAN guard.  A
		// closure over live settings so toggling a preset / adding a bypass IP
		// applies without a restart, and so it is preset + CIDR-aware: a
		// crawler range (Googlebot / Bingbot / GPTBot) landing on a honeypot
		// URI is never auto-banned (CLAUDE.md #4).  The map-based whitelist this
		// replaces saw only literal operator IPs, not presets or CIDRs.
		banMgr.SetWhitelist(func(ip string) bool {
			return nginxconf.NewIPBypassMatcher(h.SnapshotSettings().Nginx).Match(ip)
		})
		// Native-mode honeypot auto-ban: record which trap URL was hit (= hpuri
		// from the access-log line) as the reason, AND resolve the matched rule's
		// per-preset / per-URL action so it is pinned onto the ban's action
		// column.  This makes native honor the operator's per-preset choice (e.g.
		// captcha_only on a high-risk trap) on every subsequent request via the
		// ban-file "<key>|<source>|<action>" read, mirroring the forward-auth
		// honeypotDecide path.  action="" = inherit Honeypot.DefaultAction.  Reads
		// live settings (h.SnapshotSettings) so a UI action change applies without
		// a restart.  Registered here (not beside the other nlog callbacks) so h
		// exists; the startup window before this runs degrades to no callback,
		// same as the pre-existing nlog.Start()-to-callback gap.
		if nlog != nil {
			// Suppress the honeypot auto-ban for a plaintext request nginx
			// answered with a 301 (= a JA4-less access-log line while
			// https_redirect is on).  Live settings, so toggling the redirect
			// applies without a restart.  See Reader.httpsRedirectOn.
			nlog.SetHTTPSRedirectCheck(func() bool {
				return h.SnapshotSettings().Nginx.HTTPSRedirect
			})
			nlog.SetHoneypotCallback(func(ip, ja4, uri, site string) {
				reason := "honeypot"
				if uri != "" {
					if len(uri) > 200 {
						uri = uri[:200]
					}
					reason = "hit " + uri
				}
				action, _ := nginxconf.ResolveHoneypotAction(uri, site, h.SnapshotSettings().Nginx)
				banMgr.AddWithSourceAction(context.Background(), ip, ja4, ban.SourceHoneypot, reason, "", action)
			})
		}
	}

	// Community Bans client: pass SettingsGetter / SettingsUpdate through Handler.
	// The Run() goroutine handles register + periodic pull only when submit or
	// subscribe is ON.  Without ConfigPath we can't persist, so don't build the
	// client at all (h.CommunityBans=nil also ignores the BAN button's share).
	if h.ConfigPath != "" {
		h.CommunityBans = &communitybans.Client{
			UserAgent:      "unmask/" + Version,
			SettingsGetter: h.SnapshotSettings,
			SettingsUpdate: h.UpdateSettings,
		}
		// Build the client unconditionally (the BAN button's share path needs
		// it), but only start the register + periodic-pull loop once setup is
		// complete, so a fresh box doesn't register with the hub before the
		// operator has finished the wizard.  The post-setup auto re-exec starts
		// it on the next boot.
		if setupComplete {
			go h.CommunityBans.Run(context.Background(), communitybans.PullInterval)
		}
	}

	// Hub-server endpoints (= /api/feed/register, /api/feed/submit) moved
	// to the separate unmask-sh/unmask-hub private repo + binary, deployed
	// on unmask.sh only.  The legacy feed_server: yaml block is silently
	// ignored here (= yaml.v3 drops unknown fields).

	// Web Bot Auth verifier: shared cache across requests, set up once.
	// Lifetime of the Verifier matches the daemon; nothing per-request.
	h.WebBotAuth = webbotauth.New()
	// SSRF gate for the directory fetch: only fetch from allowlisted operator
	// hosts.  Reads the live settings on each call so an admin allowlist edit
	// takes effect without a restart.
	h.WebBotAuth.AllowOperator = func(host string) bool {
		return h.SnapshotSettings().Nginx.WebBotAuth.IsOperatorAllowed(host)
	}
	// Private-network directories (= intranet operators / test rigs).  Dial
	// policy is baked into the default client per call, but we read it once
	// here at boot: flipping the setting needs a daemon restart, unlike the
	// live-read allowlist above.
	h.WebBotAuth.AllowPrivateDial = h.SnapshotSettings().Nginx.WebBotAuth.AllowPrivateNetworks

	// Privacy Pass / PAT verifier: trusted issuer token-keys come from settings.
	// The verifier parses + caches them and re-parses on a config change, so an
	// admin edit to the issuer list takes effect without a restart.  Like Web
	// Bot Auth, an empty issuer list trusts nobody (fail closed).
	h.PrivacyPass = privacypass.New()
	h.PrivacyPass.SetLoader(func() []privacypass.IssuerConfig {
		return h.SnapshotSettings().Nginx.PrivacyPass.IssuerConfigs()
	})

	// IP range subscribe loop: pull aggregated bypass-IP prefixes from the
	// unmask.sh hub daily (± jitter) and overlay them onto the embed
	// snapshot.  Failure is non-fatal — embed remains the fallback.  Sync is
	// always on; opt-out is via an unreachable HubURL or future settings.
	//
	// RenderFunc re-emits http.inc / server.inc so the new prefixes show up
	// in $is_bypass_ip.  nginx -s reload is the operator's call (= predictable
	// blast radius; we don't surprise-reload nginx).  Render uses a fresh
	// settings snapshot so future config edits are honoured.
	ipSync := nginxconf.NewSync()
	ipSync.UserAgent = "unmask/" + Version
	ipSync.RenderFunc = func() error {
		cur := h.SnapshotSettings()
		out := strings.TrimSpace(cur.Nginx.OutputDir)
		if out == "" {
			return nil // no output dir configured → nothing to render
		}
		return nginxconf.Render(cur, out, Version)
	}
	h.IPRangeSync = ipSync
	go ipSync.Start(context.Background())

	mux := buildRouter(s, h)

	// Prune old rows from unmask_event every 24h (those exceeding
	// EventsRetentionDays).  Aggregates (unmask_aggregate) are kept
	// permanently.  retention <= 0 -> no-op.  Run once at startup to sweep
	// backlog from immediately after install / restart.  Snapshotting settings
	// per run inside the goroutine hot-picks up web UI saves.
	if conn != nil {
		go func() {
			runPrune := func() {
				defer safe.Recover("retention-prune") // a panic here must not kill the daemon
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				// One consistent snapshot for this run (settingsPtr is unexported;
				// SnapshotSettings hot-picks up web UI saves on the next tick).
				cfg := h.SnapshotSettings()
				// Raw traffic events.
				if retention := cfg.EventsRetentionDays; retention > 0 {
					if n, err := events.PruneOldEvents(ctx, conn, retention); err != nil {
						log.Printf("events prune: %v", err)
					} else if n > 0 {
						log.Printf("events prune: deleted %d row(s) older than %d days", n, retention)
					}
					// Per-hour, per-crawler drill-down: same retention as raw
					// events (it's derived history that backs the trend sparkline).
					if n, err := dashboard.PruneCrawlerDetailHourly(ctx, conn, retention); err != nil {
						log.Printf("crawler-detail prune: %v", err)
					} else if n > 0 {
						log.Printf("crawler-detail prune: deleted %d row(s) older than %d days", n, retention)
					}
				}
				// Admin-action audit log (independent retention; checked
				// separately so events_retention_days=0 doesn't disable it).
				if h.UserRepo != nil {
					if retention := cfg.AuditRetentionDays; retention > 0 {
						if n, err := h.UserRepo.PruneOldAudit(ctx, retention); err != nil {
							log.Printf("audit prune: %v", err)
						} else if n > 0 {
							log.Printf("audit prune: deleted %d row(s) older than %d days", n, retention)
						}
					}
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

	// Over-block circuit breaker: sample the challenge funnel every 60s and trip
	// (alert + optional auto-passthrough) when the same visitors are being
	// re-challenged instead of passing, so a challenge regression can't quietly
	// over-block real traffic for hours.  No-op until over_block_breaker is
	// enabled.  Reads h.Settings live so web UI saves take effect.
	if conn != nil {
		go h.RunOverBlockMonitor(context.Background())
	}

	// Roll new unmask_event rows into unmask_aggregate_hourly every 60s (plus a
	// startup pass).  The stats page reads those hourly rollups instead of
	// scanning the raw event table, which is ~10x slower under pure-Go SQLite.
	// PruneHourly trims buckets past the 32-day window roughly hourly.  Fully
	// in-process: no external cron required.
	if conn != nil {
		go func() {
			runAgg := func() {
				defer safe.Recover("hourly-aggregate") // panic must not kill the daemon
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				if err := dashboard.AggregateHourly(ctx, conn, gip); err != nil {
					log.Printf("hourly aggregate: %v", err)
				}
				// Fold per-minute traffic sketches into hourly rollups so the
				// DailyUniqueIPs card merges ~720 sketches, not ~65k rows.
				if err := dashboard.RollupTrafficHLL(ctx, conn); err != nil {
					log.Printf("traffic-hll rollup: %v", err)
				}
			}
			runPrune := func() {
				defer safe.Recover("hourly-prune")
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

	// NOTE: the query planner's statistics (sqlite_stat1) are deliberately NOT
	// refreshed from here — ANALYZE holds a write lock for its whole pass (60-70s
	// measured on a 3.4GB production DB, starving event inserts).  It runs only
	// from `unmask db-analyze` and migrate; see db.RefreshPlannerStats for why.

	listener, listenDesc, err := openListener(s.Server)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := &http.Server{
		Handler: withAccessLog(mux),
		// WriteTimeout governs the longest response Go will let a handler
		// finish before the connection is force-closed.  The dashboard's
		// renderStats caps its own work at 30s overall (= via per-card
		// context.WithTimeout + a wg.Wait race), so allow a 60s envelope
		// here -- room for the 30s queries plus template render plus
		// network drain on a slow link.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Cap headers at 64 KB (Go default is 1 MB).  /api/check runs on every
		// request and pickValidBV HMAC-verifies every _bv cookie, so 1 MB of
		// packed cookies = thousands of HMACs per request; 64 KB bounds that.
		MaxHeaderBytes: 64 << 10,
	}

	// SIGINT / SIGTERM trigger graceful shutdown.  SIGHUP is no longer
	// special-cased (= the app no longer owns a log file to reopen; the
	// init system handles routing).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			log.Printf("shutdown signal received: %s", sig)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			// Drain the event flusher queue + perform a final flush.
			events.StopFlusher()
			return
		}
	}()

	// conn is intentionally nil when the DB is unreachable at boot so the setup
	// wizard can still come up (see the conn==nil gate above) -- so don't deref
	// it here, or every DB-down install crashes instead of showing setup.
	driver := "none (setup mode)"
	if conn != nil {
		driver = string(conn.Driver)
	}
	log.Printf("unmask %s listening on %s base=%s driver=%s",
		Version, listenDesc, s.Server.BasePath, driver)
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
		// Group owner.  The socket must be group-owned by a group the web
		// server worker belongs to (it connects through group rw, see
		// SocketMode 0660).  An explicit socket_group wins; when empty we probe
		// the common web-server groups (nginx today, apache etc. planned) and
		// use the first that exists instead of hard-coding nginx.  Warn only if
		// the resolved group doesn't exist.
		// A world-writable socket (other-write bit, e.g. 0666) lets any local
		// process connect regardless of group, so group ownership is moot --
		// skip auto-detect (and its multi-group warning) and the chown.  An
		// explicit socket_group is still honored even then (harmless).
		group := s.SocketGroup
		if group == "" && mode&0o002 == 0 {
			if g, all := detectWebServerGroup(); g != "" {
				group = g
				if len(all) > 1 {
					log.Printf("socket group: multiple web server groups found (%s); using %q -- set socket_group explicitly if the front-end is not %s", strings.Join(all, ", "), g, g)
				}
			} else {
				group = "nginx" // none found; keep nginx as the warning label below
			}
		}
		if group != "" {
			if g, err := osuser.LookupGroup(group); err == nil {
				gid, _ := strconv.Atoi(g.Gid)
				if err := os.Chown(path, -1, gid); err != nil {
					log.Printf("socket chown :%s failed: %v (insufficient permission?  socket stays at default uid)", group, err)
				}
			} else {
				log.Printf("socket group %q lookup failed: %v (chown skipped; the web server worker may not be able to read it.  change socket_group or run groupadd)", group, err)
			}
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

// detectWebServerGroup probes the common web server groups and returns the
// first existing one plus the full list of those that exist (or "", nil when
// none).  The unix socket is group-owned by the web server's group so its
// worker can connect (group rw); that group differs by web server / distro --
// nginx, apache (RHEL), www-data (Debian/Ubuntu), http (Arch).  Probing keeps
// `socket_group: ""` correct everywhere instead of assuming nginx, which
// matters once native mode grows beyond nginx (apache, …).
//
// The second return lets the caller warn when more than one is installed: the
// pick is order-based (nginx wins), so a host that runs apache behind unmask
// but also has nginx installed needs an explicit socket_group.
func detectWebServerGroup() (string, []string) {
	var found []string
	for _, cand := range []string{"nginx", "apache", "www-data", "http", "www"} {
		if _, err := osuser.LookupGroup(cand); err == nil {
			found = append(found, cand)
		}
	}
	if len(found) == 0 {
		return "", nil
	}
	return found[0], found
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

func buildRouter(s settings.Settings, h *handlers.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	base := strings.TrimRight(s.Server.BasePath, "/")

	// Hub endpoints (/api/feed/register, /api/feed/submit) live in the
	// separate unmask-hub binary now.  Clients still default to
	// https://unmask.sh/api/feed/{register,submit} (= DefaultCommunityBans*URL
	// in settings/CommunityBans).

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
	// Ban-deny path (nginx rewrites a deny-action ban into /unmask/_ban<orig URI>
	// instead of returning a bare 403).  Always the branded "blocked" page --
	// no challenge fallback, since a deny ban is a hard block.
	mux.HandleFunc(base+"/_ban/", h.ServeBanDeny)
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
	// Deny-mode rate-limit page preview (admin-only; no public variant -- the
	// deny page is operator config, not a visitor-facing test surface).
	mux.HandleFunc("GET "+base+"/admin/test/rate-deny", h.AuthMiddleware(h.PreviewRateDeny))
	// Live logo preview (admin-only): POST stashes a not-yet-saved logo in the
	// ephemeral preview store and returns a token; GET streams it back.  The
	// settings "Page design" tab points the challenge / deny preview iframes at
	// the token so the picked image shows before Save persists it.  Upload is
	// CSRF-guarded (the init_csrf fetch shim adds the header).
	mux.HandleFunc("POST "+base+"/admin/test/preview-logo", h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.RequireCSRFFunc(h.PreviewLogoUpload))))
	mux.HandleFunc("GET "+base+"/admin/test/preview-logo", h.AuthMiddleware(h.PreviewLogoServe))

	// API endpoints (default + per-site)
	mux.HandleFunc("POST "+base+"/api/verify", h.VerifyJSON)
	mux.HandleFunc("POST "+base+"/api/{site}/verify", h.VerifyJSON)
	mux.HandleFunc("GET "+base+"/api/captcha/new", h.CaptchaNew)
	mux.HandleFunc("GET "+base+"/api/{site}/captcha/new", h.CaptchaNew)
	mux.HandleFunc("POST "+base+"/api/debug", h.DebugBeacon)
	mux.HandleFunc("POST "+base+"/api/{site}/debug", h.DebugBeacon)
	mux.HandleFunc("POST "+base+"/api/bvj", h.IssueBVJ)
	mux.HandleFunc("POST "+base+"/api/{site}/bvj", h.IssueBVJ)

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
	// logout is POST-only + CSRF-checked: a GET logout link can be triggered
	// cross-site (<img src=.../admin/logout>) to force a logout.  The nav menu
	// posts a CSRF-tokened form (partial_user_menu.html).
	mux.HandleFunc("POST "+base+"/admin/logout", h.AdminIPAllowMiddleware(h.RequireCSRFFunc(h.AdminLogout)))
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
		h.AuthMiddleware(h.AdminStats))
	mux.HandleFunc("GET "+base+"/admin/api/funnel",
		h.AuthMiddleware(h.AdminFunnelJSON))
	mux.HandleFunc("GET "+base+"/admin/api/myip",
		h.AuthMiddleware(h.AdminMyIP))
	mux.HandleFunc("GET "+base+"/admin/community-bans/{$}",
		h.AuthMiddleware(h.AdminCommunityBansIndex))
	mux.HandleFunc("POST "+base+"/admin/community-bans/mute-toggle",
		h.AuthMiddleware(h.AdminCommunityBansMuteToggle))
	mux.HandleFunc("GET "+base+"/admin/community-bans/removals",
		h.AuthMiddleware(h.AdminRemovalRequestsIndex))
	mux.HandleFunc("POST "+base+"/admin/community-bans/removals/{id}",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminRemovalRequestPatch)))
	mux.HandleFunc("GET "+base+"/admin/api/community-bans/impact",
		h.AuthMiddleware(h.AdminCommunityBansImpact))
	mux.HandleFunc("GET "+base+"/admin/api/community-bans/detail",
		h.AuthMiddleware(h.AdminCommunityBansDetail))
	mux.HandleFunc("GET "+base+"/admin/api/community-bans/me/submissions",
		h.AuthMiddleware(h.AdminCommunityBansMySubmissions))
	mux.HandleFunc("POST "+base+"/admin/api/community-bans/vote",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminCommunityBansVote)))
	mux.HandleFunc("DELETE "+base+"/admin/api/community-bans/vote/{id}",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminCommunityBansVoteDelete)))
	mux.HandleFunc("POST "+base+"/admin/api/community-bans/comment",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminCommunityBansComment)))
	mux.HandleFunc("DELETE "+base+"/admin/api/community-bans/comment/{id}",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminCommunityBansCommentDelete)))
	mux.HandleFunc("DELETE "+base+"/admin/api/community-bans/submission/{id}",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminCommunityBansSubmissionDelete)))
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
	mux.HandleFunc("POST "+base+"/admin/api/iprange/sync",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminIPRangeSync)))
	// 1-click DB-IP Lite install / refresh.  Calls the same library as
	// `unmask install-ipgeo` and reloads the in-process ipgeo Reader.
	// Accepts ?kind=country (default) or ?kind=asn.
	mux.HandleFunc("POST "+base+"/admin/api/ipgeo/install",
		h.AuthMiddleware(h.RequireRole(user.RoleAdmin, h.AdminIPGeoInstall)))

	// JA4 playground (visualize "what would happen if I entered this JA4 + UA?")
	mux.HandleFunc("GET "+base+"/admin/playground/{$}",
		h.AuthMiddleware(h.AdminPlayground))
	mux.HandleFunc("POST "+base+"/admin/api/playground/eval",
		h.AuthMiddleware(h.AdminPlaygroundEval))

	// forward-auth mode endpoint (called by nginx auth_request /
	// Apache forward-auth / any forward-auth-capable proxy).
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
	seedPlannerStats(conn, s.DB)
	return nil
}

// plannerStatsAutoLimit: the largest SQLite file we will ANALYZE automatically at
// migrate time.  ANALYZE reads every index end to end and holds a write lock for
// the whole run (60-70s on a 3.4GB database); under this size it is effectively
// instant, which covers a fresh install.  Larger databases print a pointer to
// `unmask db-analyze` so the operator picks the moment.
const plannerStatsAutoLimit = 256 << 20 // 256 MiB

// seedPlannerStats gives a new database the index statistics the stats and
// bot-hunt pages need.  Without sqlite_stat1 the planner scans whole covering
// indexes for their GROUP BY / DISTINCT, so those pages slow down as events
// accumulate.  Never fatal: a missing ANALYZE only costs speed, and `unmask
// doctor` flags it.
func seedPlannerStats(conn *db.DB, cfg settings.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ok, err := conn.HasPlannerStats(ctx)
	if err != nil || ok {
		return
	}
	// Fail SAFE on an unstatable path: treat it as large.  Auto-running ANALYZE
	// on a database whose size we could not check risks the 60-70s write lock on
	// a multi-GB file — the incident this guard exists for.
	fi, err := os.Stat(cfg.SQLitePath)
	if err != nil || fi.Size() > plannerStatsAutoLimit {
		size := "unknown size"
		if err == nil {
			size = fmt.Sprintf("%d MiB", fi.Size()>>20)
		}
		fmt.Printf("note: no query-planner statistics (database %s) — run `unmask db-analyze`\n"+
			"      while traffic is low (it holds a write lock for up to a minute).\n", size)
		return
	}
	if err := conn.RefreshPlannerStats(ctx); err != nil {
		fmt.Printf("note: could not build query-planner statistics (%v); run `unmask db-analyze` later\n", err)
		return
	}
	fmt.Println("query-planner statistics built")
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
	ref := fs.String("ref", "", "look up the events carrying this support correlation id (the 'Ref' shown at the foot of the challenge / deny / ban page) and exit -- traces a blocked visitor's report back to its decision context")
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

	// --ref: one-shot lookup of a support correlation id, then exit (no tail).
	// The ref is the operator's hook from a "I'm blocked / the page won't load"
	// report to the exact serve event + its decision (verdict / flags / payload).
	if want := strings.TrimSpace(*ref); want != "" {
		if !validRef(want) {
			return fmt.Errorf("invalid ref %q (expected hex digits and dashes, e.g. a1b2c-3d4e5)", want)
		}
		rows, err := events.FetchByRef(ctx, conn, want, 50)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Fprintf(os.Stderr, "no events for ref %s\n", want)
			return nil
		}
		for _, ev := range rows {
			fmt.Printf("[%d] %s phase=%s verdict=%s flags=%d host=%s site=%s ip=%s ja4=%s\n      path=%s ua=%q\n      payload=%s\n",
				ev.ID, ev.Date, ev.Phase, ev.Verdict, ev.Flags, ev.Host, ev.Site, ev.IP, ev.JA4,
				ev.Path, truncForCLI(ev.UA, 100), ev.Payload)
		}
		return nil
	}

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
			// reason surfaces WHY a challenge / decision fired.  Prefer the
			// forced-challenge cause (payload force_reason, e.g. rate_limit /
			// honeypot) and fall back to the general reason field (e.g. a
			// bv_rebind_reject's ja4_mismatch / asn_veto, which sets `reason` not
			// `force_reason`) so those rows aren't printed as reason=-.  Stays
			// greppable: `unmask events --since 0 | grep reason=rate_limit`.
			reason := r.ForceReason
			if reason == "" {
				reason = r.Reason
			}
			if reason == "" {
				reason = "-"
			}
			fmt.Printf("[%d] %s %-9s host=%-12s site=%-8s ip=%-15s ja4=%s verdict=%s flags=%d reason=%-10s ua=%q\n",
				r.ID, r.Date, r.Phase, r.Host, r.Site, r.IP, r.JA4, r.Verdict, r.Flags, reason, truncForCLI(r.UA, 60))
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

// validRef gates the `--ref` lookup value to exactly what newRef mints: 16 hex
// chars, no separator.  Besides catching typos it keeps the value free of
// SQL/LIKE metacharacters before it reaches FetchByRef's pattern.
func validRef(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			return false
		}
	}
	return true
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
	body := fmt.Sprintf(`# unmask config (generated by unmask config-init)
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
  # Per-site challenge knobs live under default: (the multi-site v2 shape); a
  # site overrides the whole set via a sites: { <host>: {...} } block.  Fields
  # placed directly under challenge: are NOT read by the loader.
  default:
    pow_cookie_valid_seconds: 604800       # 7 days
    captcha_cookie_valid_seconds: 1209600  # 14 days
    debug_rate_limit_per_5min: 20
    challenge_html_path: ""   # empty -> use the embedded version inside the binary
    captcha:
      provider: builtin
      builtin_score_threshold: 0.5   # behavioral pass threshold (builtin only)

server:
  bind: 127.0.0.1
  port: 9477
  base_path: /unmask

global:
  # Stale-browser tier: escalate a UA pinned to an outdated Chrome (Chromium-
  # family) major to a CAPTCHA — a distributed-scraper tell.  ON for fresh
  # installs (config-init runs only when no config exists); an EXISTING install
  # upgrading keeps its file untouched and the tier stays off (defaults() is
  # false) until the operator reviews it on the UA-filter tab.  Uses a built-in
  # current-stable baseline, so no other setting is required; set
  # current_chrome_major to override.  Turn this off to disable.
  stale_browser_challenge: true

# Authentication is the internal user DB.  Create the first admin through the
# setup wizard (= open /unmask/admin/ after install; the one-time token printed
# by the package install / found in /etc/unmask/.setup-token guards it), or
# from the shell: unmask user create.
# CLI management: unmask user create / reset-password / set-role / delete
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
// `unmask user create`.)
