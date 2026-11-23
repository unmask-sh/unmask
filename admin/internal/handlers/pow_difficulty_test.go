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

// The difficulty a request is answered at: the one nginx verifies at, when
// the request came through the module and names a difficulty in range;
// otherwise the configured one.
func TestPowDifficultyFollowsTheNginxThatVerifies(t *testing.T) {
	for _, c := range []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"through the module", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: "12"}, 12},
		{"through the module, padded", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: " 21 "}, 21},
		{"through the module, none named", map[string]string{"X-Unmask-Local-Port": "443"}, 18},
		{"through the module, below the range", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: strconv.Itoa(settings.PowDifficultyMin - 1)}, 18},
		{"through the module, above the range", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: strconv.Itoa(settings.PowDifficultyMax + 1)}, 18},
		{"through the module, not a number", map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: "12a"}, 18},
		{"not through the module", map[string]string{powDifficultyHeader: "12"}, 18},
	} {
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
		for k, v := range c.hdr {
			req.Header.Set(k, v)
		}
		if got := powDifficultyFor(req, 18); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	if got := powDifficultyFor(nil, 18); got != 18 {
		t.Errorf("no request: %d, want the configured 18", got)
	}
}

// The setting was lowered and nginx has not reloaded: the plugin still
// verifies at the old difficulty, and the page asks for that one -- a page
// that asked for the new one was answered with a proof the plugin refused,
// and the visitor came back to the challenge until the reload.  Forward-auth
// and Apache have no nginx in between, and get the setting.
func TestChallengePageAsksForTheDifficultyNginxVerifiesAt(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Challenge.Default.PowDifficulty = 12 })
	asked := func(page string) string {
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
	page := plainPage(t, askPage(t, h, "203.0.113.91", "/unmask/challenge/",
		map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: "18"}))
	if got := asked(page); got != "18" {
		t.Errorf("through the module, nginx verifying at 18: the page asks for %s", got)
	}
	page = plainPage(t, askPage(t, h, "203.0.113.92", "/unmask/challenge/", map[string]string{powDifficultyHeader: "18"}))
	if got := asked(page); got != "12" {
		t.Errorf("not through the module: the page asks for %s, want the setting's 12", got)
	}
}

// A proof of work the daemon checks itself on a request through the module
// -- the one a CAPTCHA after a proof of work owes -- is checked at the
// difficulty nginx verifies at, which is the one the page asked for: the
// setting raised and nginx not yet reloaded, the page asked for the old
// difficulty, and checked at the new one its answer was refused.
func TestPowProofIsCheckedAtTheDifficultyNginxVerifiesAt(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Challenge.Default.PowDifficulty = 20 })
	const key, host = "203.0.113.93", "example.com"
	issued := time.Now().Unix()
	seed := cookies.PowSeedH(h.sigHash(), h.cfg().Secret.BVSecret, key, host, issued)
	proof := ""
	for nonce := int64(0); nonce < 1<<24 && proof == ""; nonce++ {
		if b := powZeroBits(seed, nonce); b >= 10 && b < 20 {
			proof = strconv.FormatInt(issued, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
		}
	}
	if proof == "" {
		t.Fatal("no nonce found")
	}
	ask := func(hdr map[string]string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/unmask/api/verify", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		return req
	}
	if !h.powProofFor(ask(map[string]string{"X-Unmask-Local-Port": "443", powDifficultyHeader: "10"}), proof, issued, key, host, "default") {
		t.Error("through the module, nginx verifying at 10: a proof of 10 bits was refused")
	}
	if h.powProofFor(ask(nil), proof, issued, key, host, "default") {
		t.Error("not through the module: a proof below the setting's 20 bits was taken")
	}
}
