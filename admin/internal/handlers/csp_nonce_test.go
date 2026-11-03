package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var nonceInHeaderRE = regexp.MustCompile(`'nonce-([A-Za-z0-9+/=]+)'`)

// The report-only script policy names a nonce, and the page's <script> tags
// carry the same one: the login page runs through the pre-session gate, and
// its shared partial (init_busy) is marked with nonceAttr.
func TestCSPNonceHeaderAndPageAgree(t *testing.T) {
	h := newTestHandler(t)
	rr := httptest.NewRecorder()
	h.AdminIPAllowMiddleware(h.AdminLoginGet)(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("login page: %d", rr.Code)
	}
	ro := rr.Header().Get("Content-Security-Policy-Report-Only")
	if !strings.HasPrefix(ro, "script-src 'self' 'nonce-") {
		t.Fatalf("report-only policy = %q, want script-src 'self' with a nonce", ro)
	}
	m := nonceInHeaderRE.FindStringSubmatch(ro)
	if m == nil {
		t.Fatalf("no nonce in %q", ro)
	}
	if !strings.Contains(rr.Body.String(), `<script nonce="`+m[1]+`">`) {
		t.Errorf("the page's script tag does not carry the header's nonce %s", m[1])
	}
	// The enforced policy is untouched: no script-src there yet.
	if csp := rr.Header().Get("Content-Security-Policy"); strings.Contains(csp, "script-src") {
		t.Errorf("the enforced policy must not name script-src while pages still carry unmarked scripts: %q", csp)
	}
}

// A nonce is per response: two requests, two values, or an attacker who saw
// one page could reuse its nonce in the next.
func TestCSPNonceDiffersPerResponse(t *testing.T) {
	h := newTestHandler(t)
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil))
		m := nonceInHeaderRE.FindStringSubmatch(rr.Header().Get("Content-Security-Policy-Report-Only"))
		if m == nil {
			t.Fatalf("response %d carries no nonce: %q", i, rr.Header().Get("Content-Security-Policy-Report-Only"))
		}
		if len(m[1]) < 22 {
			t.Errorf("nonce %q is shorter than 128 bits", m[1])
		}
		if seen[m[1]] {
			t.Fatalf("nonce %q repeated", m[1])
		}
		seen[m[1]] = true
	}
}

// nonceAttr renders the attribute from the page's data map and nothing from
// anything else, so a partial handed a sub-value or a nil dot still renders.
func TestNonceAttrToleratesOtherData(t *testing.T) {
	if got := nonceAttr(map[string]any{"Nonce": "abc+/="}); got != ` nonce="abc+/="` {
		t.Errorf("nonceAttr(map with Nonce) = %q", got)
	}
	for name, v := range map[string]any{
		"nil":             nil,
		"map without":     map[string]any{"Lang": "en"},
		"map empty nonce": map[string]any{"Nonce": ""},
		"struct":          struct{ Nonce string }{"x"},
		"string":          "x",
	} {
		if got := nonceAttr(v); got != "" {
			t.Errorf("nonceAttr(%s) = %q, want nothing", name, got)
		}
	}
	// Outside the middlewares there is no nonce, and the data map says so.
	if n := CSPNonceFromRequest(httptest.NewRequest(http.MethodGet, "/", nil)); n != "" {
		t.Errorf("a request that passed no middleware has nonce %q", n)
	}
	if got := cspScriptReportOnly(""); got != "script-src 'self'" {
		t.Errorf("policy without a nonce = %q", got)
	}
}
