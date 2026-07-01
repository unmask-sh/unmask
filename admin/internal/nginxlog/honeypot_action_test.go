package nginxlog

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestOnLineNativeHoneypotPerPresetAction exercises the NATIVE-mode honeypot
// per-rule action chain end-to-end, in-process.  In native mode the nginx plugin
// flags a honeypot (hp=1) and the access-log line reaches this reader; onLine
// must fire onHoneypot, and the wired callback (mirroring cmd/unmask/main.go)
// resolves the per-rule action via nginxconf.ResolveHoneypotAction and persists
// it on the ban via AddWithSourceAction.  This is the native counterpart to the
// forward-auth path (handlers.TestHoneypotDecidePerPreset / e2e scenario 47).
//
// It is a Go integration test rather than a docker e2e scenario because the
// docker harness runs nginx and the daemon in separate containers and the
// access-log unix-datagram does not deliver cross-container (a harness
// limitation, not a product issue -- production is single-host).  onLine is the
// exact dispatch path the cross-container socket would feed, so calling it
// directly covers the same logic deterministically.
func TestOnLineNativeHoneypotPerPresetAction(t *testing.T) {
	dir := t.TempDir()
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	banMgr := ban.New(conn, filepath.Join(dir, "ban.list"), time.Hour)
	// Stand in for the live honeypot DefaultAction that an empty (inherit) action
	// resolves to at flush time.
	banMgr.SetActionResolver(func(source string) string {
		if source == ban.SourceHoneypot {
			return "pow_then_captcha"
		}
		return "deny"
	})
	banMgr.Start()
	defer banMgr.Close()

	// One custom honeypot URL with a per-rule captcha_only override; the
	// wordpress preset (default-on, no override) is the inherited-chain control.
	var n settings.Nginx
	n.SeenVersion = "v0.1"
	n.Honeypot.URLs = []settings.HoneypotURL{
		{Path: "^/pp-captcha-trap/", Action: "captcha_only"},
		// per-site override: resolves only when the trip's site matches -- drives
		// the native per-site fix (case 4 below).
		{Path: "^/shop-trap/", Action: "deny", Site: "shop.example"},
	}

	// Reader wired exactly as cmd/unmask/main.go does.  Empty socket path: Start
	// initializes the buckets and the flush loop but binds no socket / recv loop,
	// so onLine can be driven directly.
	r := Start("", conn)
	defer r.Close()
	r.SetSearchBotCheck(func(ua string) bool { return strings.Contains(ua, "Googlebot") })
	r.SetHoneypotCallback(func(ip, ja4, uri, site string) {
		action, _ := nginxconf.ResolveHoneypotAction(uri, site, n)
		banMgr.AddWithSourceAction(context.Background(), ip, ja4, ban.SourceHoneypot, "hit "+uri, "", action)
	})

	ctx := context.Background()
	line := func(ip, site, hpuri, ua string) string {
		return "1700000000.0 site=" + site + " kind= fc=1 hp=1 ip=" + ip + " ja4=t13d1516h2 hpuri=" + hpuri + " ua=" + ua
	}

	// 1) override trap -> captcha_only persisted on the ban (native path).
	r.onLine(line("198.51.100.48", "default", "/pp-captcha-trap/x", "Mozilla/5.0 Chrome"))
	if act, src, banned := banMgr.IsBannedActionSource(ctx, "198.51.100.48", ""); !banned || src != ban.SourceHoneypot || act != "captcha_only" {
		t.Errorf("override trap: banned=%v src=%q act=%q, want honeypot/captcha_only", banned, src, act)
	}

	// 2) control: default-chain honeypot (wordpress preset, no override) bans with
	//    the inherited chain ("" row action), NOT captcha_only.
	r.onLine(line("198.51.100.49", "default", "/wp-login.php", "Mozilla/5.0 Chrome"))
	if act, _, banned := banMgr.IsBannedActionSource(ctx, "198.51.100.49", ""); !banned || act == "captcha_only" {
		t.Errorf("control trap: banned=%v act=%q, want banned with a non-captcha_only (inherited) action", banned, act)
	}

	// 3) a rescued search/AI crawler hitting a honeypot must NOT be banned
	//    (CLAUDE.md #4: never block Googlebot, even on a trap URL).
	r.onLine(line("66.249.66.1", "default", "/wp-login.php", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"))
	if _, _, banned := banMgr.IsBannedActionSource(ctx, "66.249.66.1", ""); banned {
		t.Error("search-bot honeypot hit was banned -- the rescue exemption did not apply")
	}

	// 4) per-site override resolves in NATIVE mode now that onHoneypot carries
	//    site (the fix: previously site="" dropped a per-site rule to the
	//    inherited chain).  The matching host's trip gets the per-row action.
	r.onLine(line("198.51.100.50", "shop.example", "/shop-trap/x", "Mozilla/5.0 Chrome"))
	if act, _, banned := banMgr.IsBannedActionSource(ctx, "198.51.100.50", ""); !banned || act != "deny" {
		t.Errorf("per-site trap on matching host: banned=%v act=%q, want deny (per-site override resolved in native)", banned, act)
	}
}
