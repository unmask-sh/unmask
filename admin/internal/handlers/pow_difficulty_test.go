package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The difficulty the page asks for: the stricter of the configured one and
// the one nginx verifies at, when the request came through the module and
// names a difficulty in range; otherwise the configured one.  The header
// never lowers it.
func TestPagePowDifficultyIsTheStricterOfTheSettingAndNginx(t *testing.T) {
	for _, c := range []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"nginx still at a higher one (the setting was lowered)", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: "21"}, 21},
		{"nginx still at a lower one (the setting was raised)", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: "12"}, 18},
		{"padded", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: " 21 "}, 21},
		{"none named", map[string]string{"X-Unmask-Local-Port": "443"}, 18},
		{"below the range", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: strconv.Itoa(settings.PowDifficultyMin - 1)}, 18},
		{"above the range", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: strconv.Itoa(settings.PowDifficultyMax + 1)}, 18},
		{"not a number", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: "21a"}, 18},
		{"not through the module", map[string]string{powDifficultyHeader: "21"}, 18},
	} {
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
		for k, v := range c.hdr {
			req.Header.Set(k, v)
		}
		if got := pagePowDifficulty(req, 18); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	if got := pagePowDifficulty(nil, 18); got != 18 {
		t.Errorf("no request: %d, want the configured 18", got)
	}
}

// askedDifficulty reads the difficulty a served page asks for.
func askedDifficulty(t *testing.T, page string) string {
	t.Helper()
	const mark = "/*__POW_DIFFICULTY__*/"
	i := strings.Index(page, mark)
	if i < 0 {
		t.Fatalf("the page names no difficulty")
	}
	rest := page[i+len(mark):]
	n := 0
	for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
		n++
	}
	return rest[:n]
}

// The setting was lowered and nginx has not reloaded: the plugin still
// verifies at the old difficulty, and the page asks for that one -- a page
// that asked for the new one was answered with a proof the plugin refused,
// and the visitor came back to the challenge until the reload.  A setting
// raised is asked for at once.  Forward-auth and Apache have no nginx in
// between, and get the setting.
func TestChallengePageAsksForADifficultyNginxAccepts(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Challenge.Default.PowDifficulty = 12 })
	page := plainPage(t, askPage(t, h, "203.0.113.91", "/unmask/challenge/",
		map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: "18"}))
	if got := askedDifficulty(t, page); got != "18" {
		t.Errorf("lowered to 12, nginx verifying at 18: the page asks for %s", got)
	}
	page = plainPage(t, askPage(t, h, "203.0.113.92", "/unmask/challenge/", map[string]string{powDifficultyHeader: "18"}))
	if got := askedDifficulty(t, page); got != "12" {
		t.Errorf("not through the module: the page asks for %s, want the setting's 12", got)
	}
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Challenge.Default.PowDifficulty = 20 })
	page = plainPage(t, askPage(t, h, "203.0.113.94", "/unmask/challenge/",
		map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: "12"}))
	if got := askedDifficulty(t, page); got != "20" {
		t.Errorf("raised to 20, nginx verifying at 12: the page asks for %s", got)
	}
}

// lowProof answers the seed of (key, host, issued) with a proof of at least
// low bits and fewer than high: one a difficulty of low accepts and a
// difficulty of high refuses.
func lowProof(t *testing.T, h *Handler, key, host string, issued int64, low, high int) string {
	t.Helper()
	seed := cookies.PowSeedH(h.sigHash(), h.cfg().Secret.BVSecret, key, host, issued)
	for nonce := int64(0); nonce < 1<<24; nonce++ {
		if b := powZeroBits(seed, nonce); b >= low && b < high {
			return strconv.FormatInt(issued, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
		}
	}
	t.Fatal("no nonce found")
	return ""
}

// The daemon checks a proof of work at the configured difficulty, whatever
// difficulty a request names.  Forward-auth and Apache fronts pass a
// client's X-Unmask-Local-Port and X-Unmask-Pow-Difficulty through; when the
// checks read the header, a client there named 8 bits, answered them, and
// POST /api/bvj minted the credential a re-bind turns into a pass.
func TestANamedDifficultyLowersNoCheckOfTheDaemons(t *testing.T) {
	h := newRebindTestHandler(t)
	const secret, host, key = "test-secret", "example.com", "203.0.113.93"
	h.SetSettings(settings.Settings{
		Secret:    settings.Secret{BVSecret: secret},
		Challenge: settings.ChallengeConfig{Default: settings.ChallengeValues{PowDifficulty: 16}},
	})
	issued := time.Now().Unix()
	cheap := lowProof(t, h, key, host, issued, 8, 16)
	named := func(r *http.Request) *http.Request {
		r.Header.Set("X-Unmask-Local-Port", "443")
		r.Header.Set(powDifficultyHeader, "8")
		return r
	}

	// The proof a CAPTCHA after a proof of work owes.
	req := named(httptest.NewRequest(http.MethodPost, "https://example.com/unmask/api/verify", nil))
	if h.powProofFor(req, cheap, issued, key, host, "default") {
		t.Error("a proof below the configured 16 bits was taken for a chain's proof, because the request named 8")
	}

	// The credential a re-bind turns into a pass.
	req = named(httptest.NewRequest(http.MethodPost, "https://example.com/unmask/api/bvj", nil))
	req.Header.Set("X-Real-IP", key)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0")
	req.Header.Set("X-Client-JA4", "t13d1717h2_5b57614c22b0_3cbfd9057e0d")
	req.AddCookie(&http.Cookie{Name: "_bv", Value: cheap})
	rr := httptest.NewRecorder()
	h.IssueBVJ(rr, req)
	if rr.Code != http.StatusForbidden || setCookie(rr, "_bvj") != "" {
		t.Errorf("POST /api/bvj with a proof below the configured 16 bits and a named difficulty of 8: status %d, _bvj %q; want 403 and none",
			rr.Code, setCookie(rr, "_bvj"))
	}

	// The same client with a proof the configured difficulty accepts is given one.
	full := lowProof(t, h, key, host, issued, 16, 64)
	req = httptest.NewRequest(http.MethodPost, "https://example.com/unmask/api/bvj", nil)
	req.Header.Set("X-Real-IP", key)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0")
	req.Header.Set("X-Client-JA4", "t13d1717h2_5b57614c22b0_3cbfd9057e0d")
	req.AddCookie(&http.Cookie{Name: "_bv", Value: full})
	rr = httptest.NewRecorder()
	h.IssueBVJ(rr, req)
	if rr.Code != http.StatusOK || setCookie(rr, "_bvj") == "" {
		t.Errorf("POST /api/bvj with a proof of the configured difficulty: status %d, _bvj %q; want 200 and a credential (%s)",
			rr.Code, setCookie(rr, "_bvj"), rr.Body.String())
	}
}
