package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// breakerHandler: a handler whose over-block breaker is tripped with
// auto_passthrough on -- the one state in which ServeChallenge hands out a pass
// cookie instead of a challenge.
func breakerHandler(t *testing.T) *Handler {
	t.Helper()
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.OverBlock.AutoPassthrough = true })
	h.overBlockTripped.Store(true)
	return h
}

// The breaker's pass-through must issue a PROPERLY-SIGNED _bv.  The native C
// plugin (and the Go /api/check verifier) check the HMAC and reject an unsigned
// sentinel, so the old "passthrough.0.c" placeholder re-challenged forever in
// native mode -- the web1-jp production loop where pass-through could not
// recover the site.
func TestServeChallenge_BreakerPassthroughIssuesVerifiableBV(t *testing.T) {
	h := breakerHandler(t)

	req := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	req.Header.Set("X-Real-IP", "203.0.113.5")
	req.Header.Set("X-Original-Host", "shop.example.com")
	w := httptest.NewRecorder()

	h.ServeChallenge(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("breaker passthrough: want 302 redirect, got %d", res.StatusCode)
	}
	var bv string
	for _, c := range res.Cookies() {
		if c.Name == "_bv" {
			bv = c.Value
		}
	}
	if bv == "" {
		t.Fatal("breaker passthrough: no _bv cookie issued")
	}
	if bv == "passthrough.0.c" {
		t.Fatal("passthrough _bv is still the unsigned sentinel -> native plugin rejects -> loop")
	}
	// Must verify against the SAME ip+host the plugin folds into its HMAC, or
	// the cookie is rejected on the next request and the visitor loops.
	if !cookies.Verify(bv, h.cfg().Secret.BVSecret, "203.0.113.5", "shop.example.com", 604800, 1209600, 18) {
		t.Errorf("passthrough _bv %q does not verify (native plugin would reject -> loop)", bv)
	}
}

// The visitor the breaker lets through goes back to the page they asked for.
// Every dispatcher carries it as _orig (protect.inc's rewrite, the apache
// snippet); this branch read "orig" and sent everyone to /.
func TestServeChallenge_BreakerPassthroughReturnsToOrig(t *testing.T) {
	h := breakerHandler(t)

	for _, tc := range []struct{ orig, want string }{
		// read from the query string, so the value arrives decoded
		{"/wp-login.php?redirect_to=%2Fwp-admin%2F", "/wp-login.php?redirect_to=/wp-admin/"},
		{"/docs/", "/docs/"},
		// A client-supplied off-site target is never echoed into Location.
		{"//evil.example/", "/"},
		{"https://evil.example/x", "/"},
	} {
		req := httptest.NewRequest("GET", "/unmask/challenge/?_orig="+tc.orig, nil)
		req.Header.Set("X-Real-IP", "203.0.113.6")
		w := httptest.NewRecorder()
		h.ServeChallenge(w, req)
		if got := w.Result().Header.Get("Location"); got != tc.want {
			t.Errorf("_orig=%q: Location = %q, want %q", tc.orig, got, tc.want)
		}
	}
}

// Without the breaker nothing hands out a free cookie: the operator-facing
// pass-through switch is gone, so a plain challenge-route request is served the
// challenge.
func TestServeChallenge_NoFreeCookieWithoutTheBreaker(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/unmask/challenge/?_orig=/", nil)
	req.Header.Set("X-Real-IP", "203.0.113.7")
	w := httptest.NewRecorder()
	h.ServeChallenge(w, req)
	if w.Result().StatusCode == http.StatusFound {
		t.Fatal("the challenge route redirected without the breaker being tripped")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "_bv" {
			t.Fatalf("a _bv was handed out without a solve: %q", c.Value)
		}
	}
}
