package nginxlog

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A honeypot trip read from the access log must NOT create an auto-ban when the
// line carries no JA4 while https_redirect is on.
//
// No JA4 means the request carried no TLS -- a handshake always sends a
// ClientHello, even a resumed session (PSK), so the module fingerprints every
// TLS connection -- i.e. it arrived on the plaintext port.  With https_redirect
// on nginx answers it with a 301 and never serves it, but access_log is still
// evaluated at request completion and $serve_bot_challenge only tests the URI.
// A scanner probing a honeypot path over :80 therefore produced an "hp=1 ja4=-"
// line and earned a scope=ip_only ban on its WHOLE IP -- broader than, and a
// duplicate of, the precise (ip, ja4) ban its HTTPS visit already earns.
// Reproduced on tool1-jp 2026-07-14: one plaintext curl to a honeypot path
// returned 301 and still banned the caller.
//
// With https_redirect off the operator has deliberately kept the plaintext port
// under inspection, so those bans must still fire.
//
// Driven through onLine (the exact dispatch the access-log socket feeds) rather
// than a docker e2e scenario: the docker harness runs nginx and the daemon in
// separate containers and the access-log unix-datagram does not deliver
// cross-container, so nginx_log.enabled is off there (a harness limitation, not
// a product issue -- production is single-host).  Same rationale as
// TestOnLineNativeHoneypotPerPresetAction.
func TestOnLineHoneypotPlaintextRedirectVeto(t *testing.T) {
	const (
		ja4Real  = "t13d201100_2b729b4bf6f3_36bf25f296df"
		hpURI    = "/wp-admin/css/"
		scanIP   = "203.0.113.80"
		scanUA   = "Mozilla/5.0 (compatible; scanner)"
		hpReason = "hit " + hpURI
	)
	tests := []struct {
		name          string
		ja4           string // "" renders as the access log's ja4=- placeholder
		httpsRedirect bool
		wantBan       bool
	}{
		{"plaintext trip while redirecting -> vetoed", "", true, false},
		{"TLS trip while redirecting -> banned", ja4Real, true, true},
		{"plaintext trip, redirect off -> banned", "", false, true},
		{"TLS trip, redirect off -> banned", ja4Real, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
			if err != nil {
				t.Fatalf("db open: %v", err)
			}
			if err := db.Migrate(conn); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			banFile := filepath.Join(dir, "ban.list")
			banMgr := ban.New(conn, banFile, time.Hour)
			banMgr.SetActionResolver(func(string) string { return settings.RateChallengeCaptchaOnly })
			banMgr.Start()
			defer banMgr.Close()

			r := &Reader{}
			r.SetHTTPSRedirectCheck(func() bool { return tc.httpsRedirect })
			var got []string
			r.SetHoneypotCallback(func(ip, ja4, uri, site string) {
				got = append(got, ip)
				banMgr.AddWithSourceAction(t.Context(), ip, ja4, ban.SourceHoneypot,
					"hit "+uri, "", "")
			})

			// The access log renders a missing JA4 as "-"; parse() normalizes it
			// back to "" (the fix that made these lines reach the ban path at all).
			ja4Field := tc.ja4
			if ja4Field == "" {
				ja4Field = "-"
			}
			line := "1783938726.123 site=example.com kind= fc=1 hp=1 ip=" + scanIP +
				" ja4=" + ja4Field + " hpuri=" + hpURI + " ua=" + scanUA
			r.onLine(line)

			banned := len(got) > 0
			if banned != tc.wantBan {
				t.Fatalf("honeypot ban created = %v, want %v (ja4=%q https_redirect=%v)",
					banned, tc.wantBan, tc.ja4, tc.httpsRedirect)
			}
			if !tc.wantBan {
				return
			}
			if got[0] != scanIP {
				t.Errorf("banned ip = %q, want %q", got[0], scanIP)
			}
		})
	}
}

// The search-bot veto must keep working now that it shares honeypotBanAllowed
// with the plaintext one -- a rescued crawler is never banned, JA4 or not.
func TestOnLineHoneypotSearchBotVetoStillApplies(t *testing.T) {
	r := &Reader{}
	r.SetSearchBotCheck(func(ua string) bool { return strings.Contains(ua, "Googlebot") })
	r.SetHTTPSRedirectCheck(func() bool { return false })
	var banned []string
	r.SetHoneypotCallback(func(ip, ja4, uri, site string) { banned = append(banned, ip) })

	r.onLine("1783938726.123 site=example.com kind= fc=1 hp=1 ip=66.249.66.1 " +
		"ja4=t13d1516h2_8daaf6152771_02713d6af862 hpuri=/wp-login.php " +
		"ua=Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	if len(banned) != 0 {
		t.Errorf("a rescued search bot was honeypot-banned: %v", banned)
	}
}
