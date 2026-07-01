package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Passthrough ("全通過モード") must issue a PROPERLY-SIGNED _bv.  The native C
// plugin (and the Go /api/check verifier) check the HMAC and reject an unsigned
// sentinel, so the old "passthrough.0.c" placeholder re-challenged forever in
// native mode -- the tool1-jp production loop where "全通過モードで復旧できない".
func TestServeChallenge_PassthroughIssuesVerifiableBV(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Global.Passthrough = true })

	req := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	req.Header.Set("X-Real-IP", "203.0.113.5")
	req.Header.Set("X-Original-Host", "shop.example.com")
	w := httptest.NewRecorder()

	h.ServeChallenge(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("passthrough: want 302 redirect, got %d", res.StatusCode)
	}
	var bv string
	for _, c := range res.Cookies() {
		if c.Name == "_bv" {
			bv = c.Value
		}
	}
	if bv == "" {
		t.Fatal("passthrough: no _bv cookie issued")
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
