package nginxconf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestNginxMatchesPrefixBansAsTheDaemonDoes runs a real nginx with the module
// on a ban file the daemon's own manager wrote, and asks both about the same
// clients.  The daemon answers from its picture of the list (ban.mirror: the
// narrowest prefix an address lies in decides, and a v4-mapped address is the
// IPv4 address it carries); the module has to give the same answer, because
// the daemon's is what the admin shows and what forward-auth enforces, and
// the module's is what nginx does.
//
// Two ways it did not.  The file is sorted by key as text, so "10.0.0.0/8|"
// comes ahead of "10.1.0.0/16|", and the module returned the first row an
// address lay in: of an operator's "CAPTCHA for the /8" and "deny the /16
// inside it", the /8 decided.  And the module compared address families
// before anything else, so an IPv4 prefix never matched a client nginx saw
// as "::ffff:a.b.c.d" -- an IPv4 client on a listener that takes both
// families, or an address a proxy wrote that way.
//
// Skipped unless UNMASK_TEST_NGINX and UNMASK_TEST_NGINX_MODULE are set:
// `make test-nginx-accepts` sets both.
func TestNginxMatchesPrefixBansAsTheDaemonDoes(t *testing.T) {
	bin, mod := os.Getenv("UNMASK_TEST_NGINX"), os.Getenv("UNMASK_TEST_NGINX_MODULE")
	if bin == "" || mod == "" {
		t.Skip("UNMASK_TEST_NGINX / UNMASK_TEST_NGINX_MODULE are not set")
	}
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	banFile := filepath.Join(dir, "banned.txt")
	mgr := ban.New(d, banFile, time.Hour)
	mgr.Start() // the loop that writes the file
	t.Cleanup(mgr.Close)
	ctx := context.Background()
	for _, row := range []struct{ ip, action string }{
		// Wider first in the file's order (it is sorted as text), narrower
		// inside: the narrower has to decide.
		{"10.0.0.0/8", "captcha_only"},
		{"10.1.0.0/16", "deny"},
		{"10.1.2.0/24", "pow_only"},
		{"10.1.2.3", "captcha_only"}, // one address: an exact row, ahead of every prefix
		{"192.0.2.0/24", "deny"},
		{"2001:db8::/32", "captcha_only"},
		{"2001:db8:1::/48", "deny"},
	} {
		if err := mgr.AddManualWithScope(ctx, row.ip, "", ban.ScopeIPOnly, "test", "op", row.action, 0); err != nil {
			t.Fatalf("ban %s: %v", row.ip, err)
		}
	}
	// The manager writes the file from its loop, a short while after the
	// last ban; wait for the last row to be in it.
	var file []byte
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		file, _ = os.ReadFile(banFile)
		if strings.Contains(string(file), "2001:db8:1::/48|") && strings.Contains(string(file), "10.1.2.3|") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the manager did not write every ban to %s:\n%s", banFile, file)
		}
	}
	// The premise: the file names the /8 ahead of the /16 inside it.
	if i, j := strings.Index(string(file), "10.0.0.0/8|"), strings.Index(string(file), "10.1.0.0/16|"); i < 0 || j < 0 || i > j {
		t.Fatalf("the ban file does not name 10.0.0.0/8 ahead of 10.1.0.0/16:\n%s", file)
	}

	// The clients arrive through a proxy on loopback that names them in
	// X-Forwarded-For; the realip module turns that into the address the
	// module sees, a v4-mapped one as written.
	ask, _ := startNginxWith(t, bin, mod, "nginx:\n  honeypot:\n    ban_file_path: \""+banFile+"\"\n",
		"$remote_addr|$unmask_banned|$unmask_ban_action",
		"    set_real_ip_from 127.0.0.1;\n    real_ip_header X-Forwarded-For;\n")
	banned := 0
	for _, c := range []struct{ client, why string }{
		{"10.9.9.9", "in the /8 alone"},
		{"10.1.9.9", "in the /8 and the /16: the /16 decides"},
		{"10.1.2.9", "in all three: the /24 decides"},
		{"10.1.2.3", "the exact row, ahead of the prefixes it lies in"},
		{"192.0.2.77", "in the one /24"},
		{"11.0.0.1", "in no row"},
		{"::ffff:10.9.9.9", "v4-mapped, in the /8"},
		{"::ffff:10.1.9.9", "v4-mapped, in the /8 and the /16"},
		{"::ffff:192.0.2.77", "v4-mapped, in the /24"},
		{"::ffff:11.0.0.1", "v4-mapped, in no row"},
		{"2001:db8:2::5", "in the /32 alone"},
		{"2001:db8:1::5", "in the /32 and the /48: the /48 decides"},
		{"2001:db9::1", "IPv6, in no row"},
	} {
		action, source, isBanned := mgr.IsBannedActionSource(ctx, c.client, "")
		want := c.client + "|0|"
		if isBanned {
			banned++
			want = c.client + "|1|" + mgr.EffectiveAction(action, source)
		}
		if got := ask(false, map[string]string{"X-Forwarded-For": c.client}); got != want {
			t.Errorf("%s (%s): nginx says addr|banned|action = %q, the daemon %q", c.client, c.why, got, want)
		}
	}
	if banned != 10 {
		t.Errorf("the daemon bans %d of the clients, want 10: the table does not test what it says", banned)
	}
	// What the daemon says of the two cases the module got wrong, spelt out,
	// so that a change to the daemon's own rule shows here as well.
	for client, want := range map[string]string{"10.1.9.9": "deny", "10.1.2.9": "pow_only", "::ffff:10.1.9.9": "deny", "2001:db8:1::5": "deny", "10.1.2.3": "captcha_only"} {
		action, source, isBanned := mgr.IsBannedActionSource(ctx, client, "")
		if got := mgr.EffectiveAction(action, source); !isBanned || got != want {
			t.Errorf("the daemon on %s: banned=%v action=%q, want %q", client, isBanned, got, want)
		}
	}
}
