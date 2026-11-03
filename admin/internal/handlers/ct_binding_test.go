package handlers

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/captcha"
	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// postSignal answers the behavioral CAPTCHA under ct from ip, with the
// headers given, and returns the recorder.
func postSignal(t *testing.T, h *Handler, ip, ct, pow string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"token": "x", "ct": ct, "pow": pow,
		"sig": map[string]any{"hasMouseEvents": true, "clickAt": 3000, "windowSize": []int{1440, 900},
			"mouseTrail": [][]float64{{10, 10, 1}, {40, 33, 80}, {70, 55, 160}, {100, 77, 240}, {130, 99, 320}}}}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", ip)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.VerifyJSON(rr, req)
	return rr
}

// bvKindOf is the kind of the entry the verify issued: the newest, which
// AppendEntry puts first in the "~"-list (an entry the request carried
// follows it).
func bvKindOf(rr *httptest.ResponseRecorder) string {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_bv" {
			first, _, _ := strings.Cut(c.Value, "~")
			parts := strings.Split(first, ".")
			return parts[len(parts)-1]
		}
	}
	return ""
}

// solvePoW answers the seed the page served at issued handed key on host: the
// cookie entry challenge.js writes, "<issued>.pow2.<nonce base36>.0".
func solvePoW(t *testing.T, h *Handler, key, host string, issued int64, diff int) string {
	t.Helper()
	seed := cookies.PowSeedH(h.sigHash(), h.cfg().Secret.BVSecret, key, host, issued)
	for nonce := int64(0); nonce < 1<<26; nonce++ {
		sum := sha256.Sum256([]byte(seed + ":" + strconv.FormatInt(nonce, 10)))
		bits := 0
		for _, v := range sum {
			if v == 0 {
				bits += 8
				continue
			}
			for m := byte(0x80); m != 0 && v&m == 0; m >>= 1 {
				bits++
			}
			break
		}
		if bits >= diff {
			return strconv.FormatInt(issued, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
		}
	}
	t.Fatal("no nonce found")
	return ""
}

// The token is the client's: another host, or another TLS stack over the
// same transport, is refused; the device's own fingerprint drift -- a resumed
// session, the QUIC side -- and a deployment with no fingerprint are not.
func TestVerifyJSON_CtBoundToHostAndFingerprint(t *testing.T) {
	h := newTestHandler(t)
	const ip = "203.0.113.50"
	const chrome = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	issue := func(host, ja4 string) string {
		return captcha.IssueToken("test-base", time.Now().Add(-5*time.Second),
			captcha.Binding{Key: ip, Host: host, JA4: ja4, Chain: settings.RateChallengeCaptchaOnly})
	}
	// Another host.
	if rr := postSignal(t, h, ip, issue("other.example", ""), "", nil); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "stale_challenge") {
		t.Errorf("a token of another host: want 403 stale_challenge, got %d %s", rr.Code, rr.Body.String())
	}
	for _, c := range []struct {
		ja4  string
		want int
		why  string
	}{
		{chrome, http.StatusOK, "the same connection"},
		{"t13d1517h2_8daaf6152771_b0da82dd1658", http.StatusOK, "a resumed session of the same stack"},
		{"q13d0310h3_55b375c5d22e_cd85d2d88918", http.StatusOK, "the device's QUIC side"},
		{"", http.StatusOK, "no fingerprint on the answer"},
		{"t13d3112h2_e8f1e7e78f70_6f4d6a8e8a2c", http.StatusForbidden, "another TCP stack"},
	} {
		rr := postSignal(t, h, ip, issue("example.com", chrome), "", map[string]string{"X-Client-JA4": c.ja4})
		if rr.Code != c.want {
			t.Errorf("%s (%q): got %d %s, want %d", c.why, c.ja4, rr.Code, rr.Body.String(), c.want)
		}
	}
}

// The chain the page ran is the ct's: a chain that solved a proof-of-work
// first has to show it, in the verify's own field or as a _bv entry, and
// the proof names this page's second.  What the CAPTCHA earns follows the
// chain too: a proof-of-work-only page never mints a CAPTCHA-grade pass.
func TestVerifyJSON_ChainOwesItsProofOfWork(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Challenge.Default.PowDifficulty = 8
	h.SetSettings(cur)
	const ip, host = "203.0.113.51", "example.com"
	issued := time.Now().Add(-5 * time.Second).Unix()
	ct := func(chain string) string {
		return captcha.IssueToken("test-base", time.Unix(issued, 0), captcha.Binding{Key: ip, Host: host, Chain: chain})
	}
	proof := solvePoW(t, h, ip, host, issued, 8)

	// pow_then_captcha: no proof, no pass.
	rr := postSignal(t, h, ip, ct(settings.RateChallengePoWThenCaptcha), "", nil)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "pow_required") || bvKindOf(rr) != "" {
		t.Fatalf("the chain's CAPTCHA without its proof-of-work: want 403 pow_required and no cookie, got %d %s", rr.Code, rr.Body.String())
	}
	// A proof of another page (another second).
	rr = postSignal(t, h, ip, ct(settings.RateChallengePoWThenCaptcha), solvePoW(t, h, ip, host, issued-30, 8), nil)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "pow_required") {
		t.Fatalf("a proof of another page: want 403 pow_required, got %d %s", rr.Code, rr.Body.String())
	}
	// A proof of another client's page.
	rr = postSignal(t, h, ip, ct(settings.RateChallengePoWThenCaptcha), solvePoW(t, h, "198.51.100.9", host, issued, 8), nil)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "pow_required") {
		t.Fatalf("another client's proof: want 403 pow_required, got %d %s", rr.Code, rr.Body.String())
	}
	// The page's own proof, in the field: a CAPTCHA-grade pass.
	rr = postSignal(t, h, ip, ct(settings.RateChallengePoWThenCaptcha), proof, nil)
	if rr.Code != http.StatusOK || bvKindOf(rr) != "captcha" {
		t.Fatalf("the chain with its proof: want 200 and a captcha pass, got %d %s kind=%q", rr.Code, rr.Body.String(), bvKindOf(rr))
	}
	// The same proof as a _bv entry on the request.
	rr = postSignal(t, h, ip, ct(settings.RateChallengePoWThenCaptcha), "", map[string]string{"Cookie": "_bv=junk~" + proof})
	if rr.Code != http.StatusOK || bvKindOf(rr) != "captcha" {
		t.Fatalf("the proof carried as a cookie: want 200 and a captcha pass, got %d %s", rr.Code, rr.Body.String())
	}
	// captcha_only owes nothing before the CAPTCHA.
	rr = postSignal(t, h, ip, ct(settings.RateChallengeCaptchaOnly), "", nil)
	if rr.Code != http.StatusOK || bvKindOf(rr) != "captcha" {
		t.Fatalf("captcha_only without a proof: want 200 and a captcha pass, got %d %s", rr.Code, rr.Body.String())
	}
	// pow_only: the page's own escalation to the CAPTCHA still owes the
	// proof, and earns what the posture asked for.
	rr = postSignal(t, h, ip, ct(settings.RateChallengePoWOnly), "", nil)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "pow_required") {
		t.Fatalf("pow_only without a proof: want 403 pow_required, got %d %s", rr.Code, rr.Body.String())
	}
	rr = postSignal(t, h, ip, ct(settings.RateChallengePoWOnly), proof, nil)
	if rr.Code != http.StatusOK || bvKindOf(rr) != "pow" {
		t.Fatalf("pow_only with its proof: want 200 and a pow pass, got %d %s kind=%q", rr.Code, rr.Body.String(), bvKindOf(rr))
	}
	// A token naming no chain this verify answers for.
	rr = postSignal(t, h, ip, ct(""), proof, nil)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "stale_challenge") {
		t.Fatalf("a token without a chain: want 403 stale_challenge, got %d %s", rr.Code, rr.Body.String())
	}
	// The arithmetic is the same leg: it owes the same proof.
	mct := ct(settings.RateChallengePoWThenCaptcha)
	a, b, tok := captcha.MathChallenge("test-base", mct)
	if res, out := postMath(t, h, ip, map[string]any{"answer": a + b, "token": tok, "ct": mct, "iv": 3, "dt": 2000}); res.StatusCode != http.StatusForbidden || out["error"] != "pow_required" {
		t.Fatalf("the arithmetic without the proof: want 403 pow_required, got %d %v", res.StatusCode, out)
	}
	if res, out := postMath(t, h, ip, map[string]any{"answer": a + b, "token": tok, "ct": mct, "pow": proof, "iv": 3, "dt": 2000}); res.StatusCode != http.StatusOK || bvKindFrom(t, res) != "captcha" {
		t.Fatalf("the arithmetic with the proof: want 200 and a captcha pass, got %d %v", res.StatusCode, out)
	}
}

var ctFromChallengeHTML = regexp.MustCompile(`/\*__CT__\*/"([^"]+)"`)

// The page's token carries the chain served and is the client's: it verifies
// for the client the page went to, under the chain the page shows, and for
// nobody else.
func TestServeChallenge_CtNamesTheChainAndTheClient(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Global.KnownBrowserAction = settings.RateChallengePoWThenCaptcha
	h.SetSettings(cur)
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	const ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Real-IP", "203.0.113.60")
	req.Header.Set("X-Client-JA4", ja4)
	req.Header.Set("X-Original-Host", "shop.example")
	rr := httptest.NewRecorder()
	h.ServeChallenge(rr, req)
	html := rr.Body.String()
	m := ctFromChallengeHTML.FindStringSubmatch(html)
	if m == nil {
		t.Fatal("the page carries no ct")
	}
	chain := chModeFromChallengeHTML(html)
	claims, ok := captcha.VerifyToken(m[1], "test-base", captcha.TokenValidSeconds, "203.0.113.60", "shop.example", ja4)
	if !ok {
		t.Fatalf("the page's ct does not verify for the client it was served to: %q", m[1])
	}
	if claims.Chain != chain || claims.Chain != settings.RateChallengePoWThenCaptcha {
		t.Errorf("the ct names chain %q, the page %q, want pow_then_captcha", claims.Chain, chain)
	}
	if claims.JA4 != ja4 {
		t.Errorf("the ct names fingerprint %q, want the serve's", claims.JA4)
	}
	if _, ok := captcha.VerifyToken(m[1], "test-base", captcha.TokenValidSeconds, "198.51.100.1", "shop.example", ja4); ok {
		t.Error("the page's ct verifies for another address")
	}
	if _, ok := captcha.VerifyToken(m[1], "test-base", captcha.TokenValidSeconds, "203.0.113.60", "example.com", ja4); ok {
		t.Error("the page's ct verifies for another host")
	}
}

// ?_force= picks the chain only on the test routes.  On the public challenge
// route the query is the visitor's, and a chain of the visitor's choosing
// would be a chain the ct signs: captcha_only, which owes no proof-of-work.
func TestServeChallenge_ForceOnlyOnTestRoutes(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Global.KnownBrowserAction = settings.RateChallengePoWOnly
	h.SetSettings(cur)
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	serve := func(path string, via func(http.ResponseWriter, *http.Request)) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Real-IP", "203.0.113.61")
		rr := httptest.NewRecorder()
		via(rr, req)
		html := rr.Body.String()
		m := ctFromChallengeHTML.FindStringSubmatch(html)
		if m == nil {
			t.Fatalf("%s: no ct in the page", path)
		}
		claims, ok := captcha.VerifyToken(m[1], "test-base", captcha.TokenValidSeconds, "203.0.113.61", "example.com", "")
		if !ok {
			t.Fatalf("%s: the ct does not verify", path)
		}
		if got := chModeFromChallengeHTML(html); got != claims.Chain {
			t.Fatalf("%s: the page shows %q, the ct names %q", path, got, claims.Chain)
		}
		return claims.Chain
	}
	if got := serve("/unmask/challenge/?_force=captcha", h.ServeChallenge); got != settings.RateChallengePoWOnly {
		t.Errorf("the public route with ?_force=captcha served %q, want the posture's pow_only", got)
	}
	if got := serve("/unmask/test/force-captcha", h.ForceCaptcha); got != settings.RateChallengeCaptchaOnly {
		t.Errorf("the test route served %q, want captcha_only", got)
	}
	if got := serve("/unmask/admin/test/force-pow-then-captcha", h.ForcePoWThenCaptcha); got != settings.RateChallengePoWThenCaptcha {
		t.Errorf("the admin test route served %q, want pow_then_captcha", got)
	}
}
