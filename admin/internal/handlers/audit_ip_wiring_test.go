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

// installedHandler returns a Handler past the setup wizard.  Both admin
// middlewares wave everything through while setup is pending -- deliberately,
// so a fresh install cannot lock itself out before any rule exists -- so a
// handler with no admin user would silently skip the checks under test.
func installedHandler(t *testing.T) *Handler {
	t.Helper()
	conn, err := db.Open(settings.DB{
		Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "w.sqlite"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(
		`INSERT INTO unmask_user (username, password_hash, role) VALUES ('probe', 'x', 'superadmin')`,
	); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: conn, UserRepo: &user.Repository{DB: conn}}
	var st settings.Settings
	st.Secret.BVSecret = "test-secret" // sessions are signed with it
	h.SetSettings(st)
	return h
}

// TestAuthMiddlewarePutsClientIPInContext: the audit log reads the client
// address from the request context, so if the middleware stops filling it in,
// every audited action silently records "from nowhere" -- with no error and no
// failing call site.  The wiring is what needs the test, not the plumbing.
func TestAuthMiddlewarePutsClientIPInContext(t *testing.T) {
	// Loopback is a trusted peer by default (forwardAuthTrustedPeers), so the
	// forwarded header is honoured exactly as it is behind a real proxy.
	h := installedHandler(t)

	var seen string
	next := func(w http.ResponseWriter, r *http.Request) {
		seen = user.ClientIPFromContext(r.Context())
	}

	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	// AuthMiddleware redirects an unauthenticated request to the login page
	// before reaching the wrapped handler, so the assertion needs a session --
	// which is also the case that matters: every audited action is authenticated.
	r.AddCookie(issueSessionCookie(h.cfg().Secret.BVSecret, 1, "superadmin", false, false))
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Real-IP", "203.0.113.9")
	h.AuthMiddleware(next)(httptest.NewRecorder(), r)

	if seen != "203.0.113.9" {
		t.Errorf("context carried %q; the audit log would record no origin", seen)
	}
}

// TestLoginMiddlewarePutsClientIPInContext: a failed login is the row whose
// origin matters most, and it is written before any session exists -- so the
// login path needs its own wiring, not the authenticated one's.
func TestLoginMiddlewarePutsClientIPInContext(t *testing.T) {
	h := installedHandler(t)
	var seen string
	next := func(w http.ResponseWriter, r *http.Request) {
		seen = user.ClientIPFromContext(r.Context())
	}

	r := httptest.NewRequest(http.MethodPost, "/unmask/admin/login", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Real-IP", "198.51.100.4")
	h.AdminIPAllowMiddleware(next)(httptest.NewRecorder(), r)

	if seen != "198.51.100.4" {
		t.Errorf("context carried %q on the login path", seen)
	}
}

// TestBlockedRequestIsNotPassedThrough: a request the allowlist rejects must
// never reach the wrapped handler, IP in context or not.
func TestBlockedRequestIsNotPassedThrough(t *testing.T) {
	h := installedHandler(t)
	cfg := *h.cfg()
	cfg.Nginx.AdminAllowedHosts = []string{"admin.example.com"}
	h.SetSettings(cfg)

	called := false
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Real-IP", "203.0.113.9")
	r.Host = "evil.example.com"
	rr := httptest.NewRecorder()
	h.AdminIPAllowMiddleware(func(http.ResponseWriter, *http.Request) { called = true })(rr, r)

	if called {
		t.Error("a request from a disallowed Host reached the handler")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", rr.Code)
	}
}
