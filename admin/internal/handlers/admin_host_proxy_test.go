package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// hostReq builds a request as it arrives at the daemon from a reverse proxy:
// Host rewritten to the backend address, the original in X-Forwarded-Host.
func hostReq(peer, host, forwarded string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil)
	r.RemoteAddr = peer
	r.Host = host
	if forwarded != "" {
		r.Header.Set("X-Forwarded-Host", forwarded)
	}
	return r
}

// TestAdminHostSeesTheVisitorsHostBehindApache: Apache's ProxyPass rewrites
// Host to the backend address by default, so admin_allowed_hosts was comparing
// "127.0.0.1:9477" against the operator's domains and refusing everyone --
// including the operator, whose only recovery was editing config.yml.  Observed
// on a live Apache 2.4.62 install: the admin UI answered "Forbidden: this Host
// (127.0.0.1:9477) is not allowed".
func TestAdminHostSeesTheVisitorsHostBehindApache(t *testing.T) {
	var cfg settings.Settings
	got := adminClientHost(hostReq("127.0.0.1:41234", "127.0.0.1:9477", "bbs.example.com"), cfg)
	if got != "bbs.example.com" {
		t.Errorf("host = %q, want the host the visitor asked for", got)
	}
}

// TestForgedForwardedHostLosesToTheProxys: mod_proxy APPENDS to a
// client-supplied X-Forwarded-Host instead of replacing it, so a visitor who
// sends one makes the daemon see "forged, real".  Reading it left-to-right --
// the X-Forwarded-For convention, where the leftmost IS the original client --
// would let any visitor name any host and walk straight through
// admin_allowed_hosts.  The concatenation here is what Apache 2.4.62 actually
// produced when asked.
func TestForgedForwardedHostLosesToTheProxys(t *testing.T) {
	var cfg settings.Settings
	got := adminClientHost(
		hostReq("127.0.0.1:41234", "127.0.0.1:9477", "admin.internal, shop.example.com"), cfg)
	if got == "admin.internal" {
		t.Fatal("the visitor's forged host won -- admin_allowed_hosts is bypassable")
	}
	if got != "shop.example.com" {
		t.Errorf("host = %q, want the value the proxy appended", got)
	}
}

// TestUntrustedPeerCannotClaimAHost: reached directly rather than through a
// proxy, X-Forwarded-Host is just something the caller typed.
func TestUntrustedPeerCannotClaimAHost(t *testing.T) {
	var cfg settings.Settings
	got := adminClientHost(hostReq("203.0.113.9:5555", "unmask.example.com:9477", "admin.internal"), cfg)
	if got != "unmask.example.com:9477" {
		t.Errorf("host = %q, want the real Host for an untrusted peer", got)
	}
}

// TestNoForwardedHostKeepsTheRealOne: the native nginx path sets no such
// header, and must keep behaving exactly as before.
func TestNoForwardedHostKeepsTheRealOne(t *testing.T) {
	var cfg settings.Settings
	got := adminClientHost(hostReq("127.0.0.1:41234", "admin.example.com", ""), cfg)
	if got != "admin.example.com" {
		t.Errorf("host = %q, want the Host header", got)
	}
}

// TestBlankForwardedHostFallsBack: a proxy that sets the header empty has told
// us nothing; the Host header is still the best answer.
func TestBlankForwardedHostFallsBack(t *testing.T) {
	var cfg settings.Settings
	if got := adminClientHost(hostReq("127.0.0.1:1", "real.example.com", "  "), cfg); got != "real.example.com" {
		t.Errorf("host = %q, want the Host header", got)
	}
	if got := adminClientHost(hostReq("127.0.0.1:1", "real.example.com", "a, "), cfg); got != "real.example.com" {
		t.Errorf("host = %q, want the Host header when the last value is blank", got)
	}
}

// TestAdminGateAdmitsTheProxiedHost: the end-to-end effect -- an operator whose
// allowlist names their domain gets in through Apache, and a domain that is not
// on the list still does not.
func TestAdminGateAdmitsTheProxiedHost(t *testing.T) {
	conn, err := db.Open(settings.DB{
		Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "gate.sqlite"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	// The gate stands down while setup is unfinished, so an install with no
	// admin yet cannot be locked out of its own wizard.  Give it one.
	if _, err := conn.Exec(
		`INSERT INTO unmask_user (username, password_hash, role) VALUES ('op','x','superadmin')`,
	); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: conn, UserRepo: &user.Repository{DB: conn}}
	var s settings.Settings
	s.Nginx.AdminAllowedHosts = []string{"bbs.example.com"}
	h.SetSettings(s)

	served := false
	gate := h.AdminIPAllowMiddleware(func(w http.ResponseWriter, r *http.Request) { served = true })

	rr := httptest.NewRecorder()
	gate(rr, hostReq("127.0.0.1:41234", "127.0.0.1:9477", "bbs.example.com"))
	if !served {
		t.Errorf("the allowed host was refused behind a proxy (status %d)", rr.Code)
	}

	served = false
	rr = httptest.NewRecorder()
	gate(rr, hostReq("127.0.0.1:41234", "127.0.0.1:9477", "elsewhere.example.com"))
	if served {
		t.Error("a host outside the allowlist was admitted")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}
