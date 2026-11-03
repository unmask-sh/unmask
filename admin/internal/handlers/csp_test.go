package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The challenge page carries a Content-Security-Policy of its own: a nonce
// per serve on its inline scripts, blob: workers for the proof-of-work, and
// the chosen CAPTCHA provider's origin.  The page used to carry none, and
// nothing said what a site's own policy would do to it.
func TestServeChallengeCarriesANoncedCSP(t *testing.T) {
	h := newTestHandler(t)
	serve := func() (*httptest.ResponseRecorder, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		csp := rr.Header().Get("Content-Security-Policy")
		m := regexp.MustCompile(`'nonce-([A-Za-z0-9+/=]+)'`).FindStringSubmatch(csp)
		if m == nil {
			t.Fatalf("no nonce in the policy %q", csp)
		}
		return rr, m[1]
	}
	rr, nonce := serve()
	body := rr.Body.String()
	if n := strings.Count(body, `<script nonce="`+nonce+`">`); n != 3 {
		t.Errorf("%d script tags carry the nonce, want 3 (two inline blocks and the inlined challenge.js)", n)
	}
	if strings.Contains(body, nonceAttrPlaceholder) {
		t.Error("the nonce placeholder is still in the page")
	}
	if !strings.Contains(body, `csp_nonce: /*__CSP_NONCE__*/"`+nonce+`"`) {
		t.Error("window.UNMASK does not carry the nonce for the scripts the page adds")
	}
	csp := rr.Header().Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self' 'nonce-", "worker-src blob:", "style-src 'self' 'unsafe-inline'", "object-src 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("policy lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "frame-ancestors") {
		t.Error("the policy restricts framing; the settings page frames the challenge for its previews")
	}
	if strings.Contains(csp, "cloudflare") {
		t.Errorf("a provider origin without a provider configured: %s", csp)
	}
	if _, again := serve(); again == nonce {
		t.Error("two serves got the same nonce")
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("the page is served without nosniff")
	}

	// The provider's origin joins the policy exactly when the page will show
	// its widget.
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Challenge.Default.CaptchaProvider = settings.Captcha{Provider: "turnstile", TurnstileSiteKey: "0xSITE", TurnstileSecretKey: "0xSECRET"}
	})
	rr, _ = serve()
	csp = rr.Header().Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self' 'nonce-", "https://challenges.cloudflare.com", "frame-src 'self' https://challenges.cloudflare.com"} {
		if !strings.Contains(csp, want) {
			t.Errorf("policy with Turnstile lacks %q: %s", want, csp)
		}
	}

	// An operator's copy of the page from before the nonce is served
	// without a policy, as before, rather than with one that would refuse
	// its own scripts.
	dir := t.TempDir()
	old := strings.ReplaceAll(string(mustRead(t, "../../assets/static/challenge.html")), ` nonce="`+nonceAttrPlaceholder+`"`, "")
	if err := os.WriteFile(filepath.Join(dir, "challenge.html"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Challenge.Default.ChallengeHTMLPath = filepath.Join(dir, "challenge.html")
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	rr = httptest.NewRecorder()
	h.ServeChallenge(rr, req)
	if got := rr.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("a page without the nonce placeholder got a policy: %s", got)
	}
}

// The step-back relay's one inline script runs under a nonce too.
func TestBackRelayCarriesANoncedCSP(t *testing.T) {
	h := newTestHandler(t)
	rr := httptest.NewRecorder()
	h.ServeBackRelay(rr, httptest.NewRequest(http.MethodGet, "/unmask/static/back.html", nil))
	csp := rr.Header().Get("Content-Security-Policy")
	m := regexp.MustCompile(`'nonce-([A-Za-z0-9+/=]+)'`).FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("no nonce in the relay's policy %q", csp)
	}
	if !strings.Contains(rr.Body.String(), `<script nonce="`+m[1]+`">`) {
		t.Error("the relay's script does not carry the policy's nonce")
	}
	if strings.Contains(rr.Body.String(), "<script>") {
		t.Error("a script tag without the nonce is left in the relay")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
