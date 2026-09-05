package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every admin response carries the anti-framing / anti-retargeting headers,
// including the pages served before a session exists (login, setup,
// password reset), which used to carry none.
func TestAdminSecurityHeadersBeforeAndAfterLogin(t *testing.T) {
	h := newTestHandler(t)
	check := func(t *testing.T, label string, hdr http.Header) {
		t.Helper()
		if hdr.Get("X-Frame-Options") != "DENY" || hdr.Get("X-Content-Type-Options") != "nosniff" || hdr.Get("Referrer-Policy") != "same-origin" {
			t.Errorf("%s: missing header(s): %v", label, hdr)
		}
		csp := hdr.Get("Content-Security-Policy")
		for _, want := range []string{"frame-ancestors 'none'", "base-uri 'self'", "object-src 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP lacks %q: %q", label, want, csp)
			}
		}
		if !strings.Contains(hdr.Get("Cache-Control"), "no-store") {
			t.Errorf("%s: Cache-Control lacks no-store: %q", label, hdr.Get("Cache-Control"))
		}
	}
	// Before a session: the IP/host gate wraps login, setup and reset.
	rr := httptest.NewRecorder()
	h.AdminIPAllowMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil))
	check(t, "login (unauthenticated)", rr.Header())
	// After: AuthMiddleware, exercised without a session -- it redirects to
	// login, and the headers are set before it decides anything.
	rr = httptest.NewRecorder()
	h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil))
	check(t, "authenticated surface", rr.Header())
}
