package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var nonceInHeaderRE = regexp.MustCompile(`'nonce-([A-Za-z0-9+/=]+)'`)

// scriptTagRE: every <script start tag in a rendered page, with its
// attributes.
var scriptTagRE = regexp.MustCompile(`<script\b[^>]*>`)

// The enforced policy names a nonce, and the page's <script> tags carry the
// same one: the login page runs through the pre-session gate, and its shared
// partial (init_busy) is marked with nonceAttr.
func TestCSPNonceHeaderAndPageAgree(t *testing.T) {
	h := newTestHandler(t)
	rr := httptest.NewRecorder()
	h.AdminIPAllowMiddleware(h.AdminLoginGet)(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("login page: %d", rr.Code)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "; script-src 'self' 'nonce-") {
		t.Fatalf("policy = %q, want script-src 'self' with a nonce", csp)
	}
	m := nonceInHeaderRE.FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("no nonce in %q", csp)
	}
	tags := scriptTagRE.FindAllString(rr.Body.String(), -1)
	if len(tags) == 0 {
		t.Fatal("the login page has no script tag; the test checks nothing")
	}
	for _, tag := range tags {
		if !strings.Contains(tag, ` nonce="`+m[1]+`"`) {
			t.Errorf("%s does not carry the header's nonce %s", tag, m[1])
		}
	}
	// The directive is enforced: no report-only copy beside it, and it is
	// this origin and the nonce, nothing that would let an unmarked script
	// run ('unsafe-inline', 'unsafe-eval', a scheme, a wildcard).
	if ro := rr.Header().Get("Content-Security-Policy-Report-Only"); ro != "" {
		t.Errorf("a report-only policy is still sent: %q", ro)
	}
	if got, want := cspDirective(csp, "script-src"), "script-src 'self' 'nonce-"+m[1]+"' 'report-sample'"; got != want {
		t.Errorf("script directive = %q, want %q", got, want)
	}
	if !strings.HasSuffix(csp, "; report-uri "+h.basePath()+"/admin/csp-report") {
		t.Errorf("the policy does not end with its report-uri: %q", csp)
	}
}

// cspDirective returns the named directive of a policy, "" when it has none.
func cspDirective(csp, name string) string {
	for _, d := range strings.Split(csp, ";") {
		d = strings.TrimSpace(d)
		if d == name || strings.HasPrefix(d, name+" ") {
			return d
		}
	}
	return ""
}

// A nonce is per response: two requests, two values, or an attacker who saw
// one page could reuse its nonce in the next.
func TestCSPNonceDiffersPerResponse(t *testing.T) {
	h := newTestHandler(t)
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil))
		m := nonceInHeaderRE.FindStringSubmatch(rr.Header().Get("Content-Security-Policy"))
		if m == nil {
			t.Fatalf("response %d carries no nonce: %q", i, rr.Header().Get("Content-Security-Policy"))
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
}

// Without a nonce the directive still allows only this origin's files: the
// page's inline scripts then do not run, which is the safe side of a
// response whose scripts cannot be told from an injected one.
func TestCSPScriptSrcWithoutANonce(t *testing.T) {
	if got := cspScriptSrc(""); got != "script-src 'self' 'report-sample'" {
		t.Errorf("directive without a nonce = %q", got)
	}
	if got := cspScriptSrc("abc+/="); got != "script-src 'self' 'nonce-abc+/=' 'report-sample'" {
		t.Errorf("directive with a nonce = %q", got)
	}
	if got := adminCSP("", "/unmask"); strings.Contains(got, "nonce-") || !strings.Contains(got, "; script-src 'self' ") {
		t.Errorf("policy without a nonce = %q", got)
	}
}
