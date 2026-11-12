package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
)

// "Preview" is the challenge page's own flag: the theme tab's previews load
// the page at its own address with ?_preview=1.  The dispatcher hands a
// visitor's request over as /challenge/?_orig=<the page> and nginx appends
// the page's own arguments after it, so a page whose URL said _preview=1 --
// a CMS's draft link, or a link made to say so -- was served as a preview:
// no silent rebind for a visitor who had roamed, and the page drawn in the
// colours the link named.
func TestPreviewIsNotAVisitorsPagesQuery(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
	const ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	bvj := cookies.IssueJValue("test-secret", cookies.FingerprintHash(ja4),
		cookies.FingerprintHash(ua), "linrebind0000000000000000", 0, "example.com", "captcha")
	serve := func(t *testing.T, path, query string, roamed bool) *httptest.ResponseRecorder {
		t.Helper()
		h := newRebindTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "https://example.com"+path+query, nil)
		req.Host = "example.com"
		req.Header.Set("X-Real-IP", "203.0.113.5")
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Client-JA4", ja4)
		if roamed {
			req.AddCookie(&http.Cookie{Name: "_bvj", Value: bvj})
		}
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		return rr
	}
	const colours = "&theme=dark&_preview_custom_bg=%23010203&_preview_custom_text=%23040506"
	painted := func(rr *httptest.ResponseRecorder) bool { return strings.Contains(rr.Body.String(), "#010203") }
	rebound := func(rr *httptest.ResponseRecorder) bool { return rr.Result().Header.Get("X-Unmask-Mode") == "rebind" }

	// The theme tab's preview: the page at its own address.
	if rr := serve(t, "/unmask/challenge/", "?_test_ja4=0&_preview=1"+colours, true); rebound(rr) || !painted(rr) {
		t.Errorf("the theme tab's preview: rebound=%v, drawn in the colours it names=%v; want a page, in those colours", rebound(rr), painted(rr))
	}

	// A visitor's page whose own query says _preview=1, as the dispatcher
	// hands it over: _orig, then the page's arguments.
	page := "/article?id=7&_preview=1"
	dispatched := "?_orig=" + url.QueryEscape(page) + "&id=7&_preview=1"
	if rr := serve(t, "/unmask/challenge/", dispatched, true); !rebound(rr) {
		t.Error("a visitor who roamed, on a page whose URL says _preview=1, was not re-bound: the page's query was read as this page's flag")
	}
	if rr := serve(t, "/unmask/challenge/", dispatched+colours, false); painted(rr) {
		t.Error("a visitor's page whose URL names preview colours was drawn in them")
	}
	// The rate route carries the visitor's URI in its path and the page's
	// query whole.
	if rr := serve(t, "/unmask/_rl/article", "?id=7&_preview=1"+colours, false); painted(rr) {
		t.Error("the rate route: a visitor's page whose URL names preview colours was drawn in them")
	}
	// And a visitor's page under a directory named /admin/test/ is not one
	// of the login's test pages.
	if rr := serve(t, "/unmask/_rl/shop/admin/test/item", "?"+strings.TrimPrefix(colours, "&"), false); painted(rr) {
		t.Error("the rate route: a visitor's page under /admin/test/ was taken for a test page and drawn in the colours its URL names")
	}
}
