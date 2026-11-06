package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every admin response carries the anti-framing / anti-retargeting headers,
// including the pages served before a session exists (login, password
// reset), which used to carry none.
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
		// The script directive, enforced, under the response's nonce
		// (csp_nonce.go), and where the browser reports a refusal.
		if d := cspDirective(csp, "script-src"); !strings.HasPrefix(d, "script-src 'self' 'nonce-") {
			t.Errorf("%s: script directive = %q", label, d)
		}
		if d := cspDirective(csp, "report-uri"); d != "report-uri "+h.basePath()+"/admin/csp-report" {
			t.Errorf("%s: report-uri = %q", label, d)
		}
		if ro := hdr.Get("Content-Security-Policy-Report-Only"); ro != "" {
			t.Errorf("%s: a report-only policy is still sent: %q", label, ro)
		}
	}
	// Before a session: the IP/host gate wraps login and reset.
	rr := httptest.NewRecorder()
	h.AdminIPAllowMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil))
	check(t, "login (unauthenticated)", rr.Header())
	// After: AuthMiddleware, exercised without a session -- it redirects to
	// login, and the headers are set before it decides anything.
	rr = httptest.NewRecorder()
	h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil))
	check(t, "authenticated surface", rr.Header())
}

// The install wizard sits outside both gates (no user to sign in, no
// allowlist to lock the installer out); its routes get the same headers,
// and its handlers the nonce, from AdminHeadersMiddleware.
func TestAdminSecurityHeadersOnTheWizard(t *testing.T) {
	h := newTestHandler(t)
	rr := httptest.NewRecorder()
	var nonce string
	h.AdminHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		nonce = CSPNonceFromRequest(r)
		w.WriteHeader(http.StatusOK)
	})(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/setup/", nil))
	hdr := rr.Header()
	if hdr.Get("X-Frame-Options") != "DENY" || hdr.Get("X-Content-Type-Options") != "nosniff" || hdr.Get("Referrer-Policy") != "same-origin" {
		t.Errorf("missing header(s): %v", hdr)
	}
	csp := hdr.Get("Content-Security-Policy")
	if !strings.HasPrefix(csp, adminCSPBase+"; ") {
		t.Errorf("policy = %q, want it to start with %q", csp, adminCSPBase)
	}
	if nonce == "" || cspDirective(csp, "script-src") != "script-src 'self' 'nonce-"+nonce+"' 'report-sample'" {
		t.Errorf("the handler's nonce %q is not the policy's: %q", nonce, csp)
	}
}

// The wizard's page on a fresh install -- a setup token, no user yet -- runs
// under the policy like any other: every script tag it carries has the nonce
// the header names.  (Signed in as a superadmin the same page is the
// reconfigure wizard, which the router's walk of the admin covers.)
func TestWizardPageOnAFreshInstallCarriesThePolicyNonce(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`CREATE TABLE unmask_user (id INTEGER PRIMARY KEY, username TEXT)`); err != nil {
		t.Fatal(err)
	}
	old, oldLegacy := SetupTokenPath, legacySetupTokenPath
	SetupTokenPath = filepath.Join(t.TempDir(), ".setup-token")
	legacySetupTokenPath = ""
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = old, oldLegacy })
	if err := os.WriteFile(SetupTokenPath, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.AdminHeadersMiddleware(h.SetupGate(h.AdminSetupIndex))(rr, httptest.NewRequest(http.MethodGet, h.basePath()+"/admin/setup/", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "</html>") {
		t.Fatalf("the wizard's page: status %d, %d bytes", rr.Code, rr.Body.Len())
	}
	m := nonceInHeaderRE.FindStringSubmatch(rr.Header().Get("Content-Security-Policy"))
	if m == nil {
		t.Fatalf("no nonce in the wizard's policy: %q", rr.Header().Get("Content-Security-Policy"))
	}
	tags := scriptTagRE.FindAllString(rr.Body.String(), -1)
	if len(tags) < 2 {
		t.Fatalf("the wizard's page has %d script tag(s); the test checks nothing", len(tags))
	}
	for _, tag := range tags {
		if !strings.Contains(tag, ` nonce="`+m[1]+`"`) {
			t.Errorf("%s does not carry the header's nonce %s", tag, m[1])
		}
	}
}
