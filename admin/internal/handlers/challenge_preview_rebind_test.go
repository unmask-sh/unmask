package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
)

// TestPreviewSkipsRebind pins the theme-tab preview against a regression: an
// operator whose browser already holds a valid _bvj cookie (they solved the
// challenge on the site) must still get the challenge markup in the preview
// iframe, not the silent roaming-rebind redirect.  The rebind path serves a
// 200 page whose <script> does location.replace("/"), so the iframe would
// navigate to the actual site — which is exactly what "the preview shows the
// normal site" was.  The rebind response is identified by X-Unmask-Mode:rebind.
func TestPreviewSkipsRebind(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
	const ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"

	bvj := cookies.IssueJValue("test-secret", cookies.FingerprintHash(ja4),
		cookies.FingerprintHash(ua), "linrebind0000000000000000", 0, "example.com", "captcha")

	mkReq := func(query string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/"+query, nil)
		req.Host = "example.com"
		req.Header.Set("X-Real-IP", "203.0.113.5")
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Client-JA4", ja4)
		req.AddCookie(&http.Cookie{Name: "_bvj", Value: bvj})
		return req
	}
	isRebind := func(rr *httptest.ResponseRecorder) bool {
		return rr.Result().Header.Get("X-Unmask-Mode") == "rebind"
	}

	t.Run("preview + valid _bvj serves challenge, not rebind", func(t *testing.T) {
		h := newRebindTestHandler(t)
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, mkReq("?_test_ja4=0&_preview=1&_preview_preset=friendly"))
		if isRebind(rr) {
			t.Fatal("preview must render the challenge, but it emitted a rebind redirect (the iframe would navigate to the site)")
		}
	})

	t.Run("plain path + valid _bvj still rebinds", func(t *testing.T) {
		// Guards against over-correcting the fix: a genuine visitor must still
		// get the silent rebind rather than a fresh challenge.
		h := newRebindTestHandler(t)
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, mkReq(""))
		if !isRebind(rr) {
			t.Fatal("a real visitor with a valid _bvj should still rebind on the plain challenge path")
		}
	})
}
