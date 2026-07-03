// The optional HTTP->HTTPS redirect (settings: nginx.https_redirect) must be
// emitted at the very TOP of server.inc — before the ban / honeypot / challenge
// gates — so a plaintext request (no TLS, no JA4) returns 301 instead of being
// challenged and possibly honeypot-banned on a JA4-less row.
package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func renderServerInc(t *testing.T, mutate func(*settings.Settings)) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	if mutate != nil {
		mutate(&s)
	}
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "server.inc"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestHTTPSRedirectOffByDefault(t *testing.T) {
	got := renderServerInc(t, nil)
	if strings.Contains(got, "return 301 https://") {
		t.Errorf("https_redirect off must not emit a redirect:\n%s", got)
	}
}

func TestHTTPSRedirectEmittedBeforeGates(t *testing.T) {
	got := renderServerInc(t, func(s *settings.Settings) {
		s.Nginx.HTTPSRedirect = true
	})

	redir := strings.Index(got, "return 301 https://$host$request_uri")
	if redir < 0 {
		t.Fatalf("https_redirect on must emit the 301:\n%s", got)
	}
	// It must key off $unmask_forwarded_proto (LB + direct edge), not $scheme.
	if !strings.Contains(got, `if ($unmask_forwarded_proto = "http")`) {
		t.Errorf("redirect should test $unmask_forwarded_proto:\n%s", got)
	}

	// ACME HTTP-01 must be excluded with a rewrite-phase break BEFORE the
	// redirect, so a certbot webroot renewal on :80 isn't 301'd away from the
	// /.well-known/acme-challenge/ path.
	acme := strings.Index(got, "/.well-known/acme-challenge/")
	if acme < 0 {
		t.Errorf("ACME HTTP-01 break missing (certbot webroot renewals would break):\n%s", got)
	} else if acme > redir {
		t.Errorf("ACME break (idx %d) must precede the redirect (idx %d)", acme, redir)
	}

	// The redirect must precede every gate so `return` short-circuits them.
	for _, marker := range []string{
		`if ($unmask_ban_action_effective = "deny")`, // ban -> _ban page
		`if ($unmask_banned_effective = "1")`,        // ban -> challenge
	} {
		g := strings.Index(got, marker)
		if g < 0 {
			t.Errorf("expected gate marker missing: %q", marker)
			continue
		}
		if redir > g {
			t.Errorf("redirect (idx %d) must come before gate %q (idx %d)", redir, marker, g)
		}
	}
}
