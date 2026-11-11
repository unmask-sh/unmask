package nginxlog

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// banFixture: a migrated SQLite and a running ban manager whose honeypot rows
// deny, for the tests that follow a line from the access log to a ban.
func banFixture(t *testing.T) (*db.DB, *ban.Manager) {
	t.Helper()
	dir := t.TempDir()
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	banMgr := ban.New(conn, filepath.Join(dir, "ban.list"), time.Hour)
	banMgr.SetActionResolver(func(string) string { return "deny" })
	banMgr.Start()
	t.Cleanup(banMgr.Close)
	return conn, banMgr
}

// honeypotToBan wires a reader's honeypot callback to the ban manager the way
// serve does, and records what it was called with.
func honeypotToBan(r *Reader, banMgr *ban.Manager) *[]string {
	var calls []string
	var n settings.Nginx
	n.SeenVersion = "v0.1"
	r.SetHoneypotCallback(func(ip, ja4, uri, site, scheme string) {
		calls = append(calls, ip)
		rule, _ := nginxconf.ResolveHoneypotRule(uri, site, n)
		banMgr.AddWithSourceAction(context.Background(), ip, ja4, ban.SourceHoneypot, "hit "+uri, "", rule.Action)
	})
	return &calls
}

// A Host header with spaces in it -- which nginx before 1.21.1 accepts and
// logs as $host -- cannot write fields of its own into the line.  The parser
// read such a line as the client's fields (hp=1 and an address of the
// client's choosing), the real ones left over and ignored, and banned that
// address for a request that tripped no trap.
func TestHostWithSpacesForgesNoHoneypotLine(t *testing.T) {
	conn, banMgr := banFixture(t)
	r := Start("", conn)
	defer r.Close()
	calls := honeypotToBan(r, banMgr)

	// GET / from 198.51.100.7 with
	//   Host: x kind= fc=0 hp=1 ip=203.0.113.9 ja4=- bp=0 scheme=https
	// logged by a configuration from before the Host was held to no space.
	host := "x kind= fc=0 hp=1 ip=203.0.113.9 ja4=- bp=0 scheme=https"
	line := "<190>Nov 11 06:30:00 web1 nginx: 1762842600.123 site=" + host +
		" kind= fc=1 hp=0 ip=198.51.100.7 ja4=t13d1516h2_8daaf6152771_02713d6af862 hpuri= bp=0 scheme=https cr= rv=0123456789ab pv=0 sb=0 sfs= sfd= rh= bv= mo=0123456789abcdef ua=curl/8.5.0"
	if p, ok := r.parse(line); ok && p.ip == "203.0.113.9" {
		t.Fatalf("the line parsed as the Host's fields: ip=%q hp=%v", p.ip, p.hp)
	}
	r.onLine(line)
	if len(*calls) != 0 {
		t.Fatalf("the honeypot callback ran for %v", *calls)
	}
	if _, _, banned := banMgr.IsBannedActionSource(context.Background(), "203.0.113.9", ""); banned {
		t.Fatalf("a request that tripped no trap banned 203.0.113.9")
	}

	// The same request logged by the configuration now: the Host is not
	// logged as it was (an empty site=, as nginx 1.16 writes it), and the
	// line reads as what it is.
	clean := "<190>Nov 11 06:30:00 web1 nginx: 1762842600.123 site=" +
		" kind= fc=1 hp=0 ip=198.51.100.7 ja4=t13d1516h2_8daaf6152771_02713d6af862 hpuri= bp=0 scheme=https cr= rv=0123456789ab pv=0 sb=0 sfs= sfd= rh= bv= mo=0123456789abcdef ua=curl/8.5.0"
	p, ok := r.parse(clean)
	if !ok || p.ip != "198.51.100.7" || p.hp || p.site != "default" {
		t.Fatalf("the clean line: ok=%v ip=%q hp=%v site=%q", ok, p.ip, p.hp, p.site)
	}
}

// accessLogLine is log_format unmask_minimal for a trap hit, as nginx sends it
// to the socket.
func accessLogLine(ip, uri, sfs, sfd, rh, ua string) string {
	return "<190>Nov 11 06:30:00 web1 nginx: 1762842600.123 site=victim.example kind= fc=0 hp=1 ip=" + ip +
		" ja4=t13d1516h2_8daaf6152771_02713d6af862 hpuri=" + uri +
		" bp=0 scheme=https cr= rv=0123456789ab pv=0 sb=0 sfs=" + sfs + " sfd=" + sfd + " rh=" + rh +
		" bv= mo=0123456789abcdef ua=" + ua
}

// socketFixture: a reader listening on a real datagram socket, wired to a ban
// manager, and a client connected to it.
func socketFixture(t *testing.T) (*Reader, *ban.Manager, *net.UnixConn) {
	t.Helper()
	conn, banMgr := banFixture(t)
	sock := filepath.Join(t.TempDir(), "log.sock")
	r := Start(sock, conn)
	t.Cleanup(r.Close)
	if !r.Loaded() {
		t.Skip("could not bind the socket")
	}
	r.SetSearchBotCheck(func(ua string) bool { return strings.Contains(ua, "Googlebot") })
	honeypotToBan(r, banMgr)
	r.Receive()
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return r, banMgr, c
}

func bannedWithin(banMgr *ban.Manager, ip string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, _, b := banMgr.IsBannedActionSource(context.Background(), ip, "t13d1516h2_8daaf6152771_02713d6af862"); b {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// A long trap URL keeps the line whole, and with it the fields the ban's
// vetoes read.  The receive buffer was 4 KB: a 4 KB query string cut the line
// inside hpuri=, the Sec-Fetch and Referer fields and the User-Agent were
// gone, and the ban spared neither a visitor whose browser fetched the trap
// as another site's image nor a rescued crawler that followed a link to it.
func TestLongTrapURLKeepsTheBanVetoes(t *testing.T) {
	_, banMgr, c := socketFixture(t)
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	gbot := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	long := "/wp-login.php?x=" + strings.Repeat("A", 4100)
	for _, l := range []string{
		accessLogLine("203.0.113.11", long, "cross-site", "image", "evil.example", chrome),
		accessLogLine("198.51.100.21", long, "", "", "", gbot),
	} {
		if _, err := c.Write([]byte(l)); err != nil {
			t.Fatalf("send (%d bytes): %v", len(l), err)
		}
	}
	if bannedWithin(banMgr, "203.0.113.11", 2*time.Second) {
		t.Errorf("a visitor whose browser fetched the trap as another site's image was banned (4 KB URL)")
	}
	if bannedWithin(banMgr, "198.51.100.21", 500*time.Millisecond) {
		t.Errorf("a rescued crawler that followed a link to the trap was banned (4 KB URL)")
	}
}

// A datagram longer than the receive buffer arrives without its tail: it is
// counted and dropped, never read as a line that lost its last fields.
func TestCutDatagramIsDroppedNotRead(t *testing.T) {
	r, banMgr, c := socketFixture(t)
	huge := "/wp-login.php?x=" + strings.Repeat("A", 70*1024)
	l := accessLogLine("203.0.113.12", huge, "cross-site", "image", "evil.example", "Mozilla/5.0")
	if _, err := c.Write([]byte(l)); err != nil {
		t.Skipf("the host does not take a %d-byte datagram: %v", len(l), err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for r.TruncatedLines() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := r.TruncatedLines(); got != 1 {
		t.Fatalf("TruncatedLines = %d, want 1", got)
	}
	if bannedWithin(banMgr, "203.0.113.12", 300*time.Millisecond) {
		t.Fatalf("the cut line was read and banned its address")
	}
}
