package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A request carrying a body whose _bv is bound to another address, with a
// _bvj that vouches for the solve: re-bound in place and sent again (307),
// not answered with a page or a JSON body.
func TestBodyRebind(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
	const ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	bvj := cookies.IssueJValue("test-secret", cookies.FingerprintHash(ja4), cookies.FingerprintHash(ua),
		"linbody00000000000000000", 0, "example.com", "pow")

	post := func(target string, withBVJ bool, hdr map[string]string) (*Handler, *httptest.ResponseRecorder) {
		h := newRebindTestHandler(t)
		// The base path the challenge route lives under, as an install has
		// it: a Referer pointing at the route itself must not be a back target.
		h.SetSettings(settings.Settings{Secret: settings.Secret{BVSecret: "test-secret"}, Server: settings.Server{BasePath: "/unmask"}})
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("name=a&qty=1"))
		req.Host = "example.com"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "203.0.113.5")
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Client-JA4", ja4)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		req.AddCookie(&http.Cookie{Name: "_bv", Value: "stale"})
		if withBVJ {
			req.AddCookie(&http.Cookie{Name: "_bvj", Value: bvj})
		}
		rr := httptest.NewRecorder()
		h.ServeChallengeOrJSON(rr, req)
		return h, rr
	}
	newBV := func(rr *httptest.ResponseRecorder) string {
		for _, c := range rr.Result().Cookies() {
			if c.Name == "_bv" {
				return c.Value
			}
		}
		return ""
	}
	nav := map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Referer": "https://example.com/order/form?step=2"}

	// The gates pass: 307 back to the original URL, query and all, with the
	// re-bound entry first in the cookie.
	_, rr := post("https://example.com/unmask/challenge/?_orig=%2Forder%2Fcheck%3Fx%3D1", true, nav)
	if rr.Code != http.StatusTemporaryRedirect || rr.Header().Get("Location") != "/order/check?x=1" || rr.Header().Get("X-Unmask-Mode") != "rebind" {
		t.Fatalf("status %d location %q mode %q, want 307 to /order/check?x=1 as a rebind", rr.Code, rr.Header().Get("Location"), rr.Header().Get("X-Unmask-Mode"))
	}
	if bv := newBV(rr); !strings.HasSuffix(strings.SplitN(bv, "~", 2)[0], ".rebind") {
		t.Errorf("the 307 carries no re-bound _bv entry: %q", bv)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rr.Header().Get("Cache-Control"))
	}

	// A fetch is re-bound the same way: the browser follows a 307 with the
	// body and the cookie, whatever the caller.
	_, rr = post("https://example.com/unmask/challenge/?_orig=%2Fapi%2Fitems", true, map[string]string{"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Accept": "application/json"})
	if rr.Code != http.StatusTemporaryRedirect || rr.Header().Get("Location") != "/api/items" {
		t.Errorf("fetch: status %d location %q, want 307 to /api/items", rr.Code, rr.Header().Get("Location"))
	}

	// The gates refuse (no _bvj): a browser's form post goes back to the page
	// it was posted from; a fetch gets the JSON refusal as before.
	_, rr = post("https://example.com/unmask/challenge/?_orig=%2Forder%2Fcheck", false, nav)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/order/form?step=2" || rr.Header().Get("X-Unmask-Mode") != "back" {
		t.Errorf("refused form: status %d location %q mode %q, want 303 to the form page", rr.Code, rr.Header().Get("Location"), rr.Header().Get("X-Unmask-Mode"))
	}
	if newBV(rr) != "" {
		t.Error("a refused post was given a _bv")
	}
	_, rr = post("https://example.com/unmask/challenge/?_orig=%2Fapi%2Fitems", false, map[string]string{"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Accept": "application/json"})
	if rr.Code != http.StatusForbidden || !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("refused fetch: status %d type %q, want the 403 JSON", rr.Code, rr.Header().Get("Content-Type"))
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body["error"] != "challenge_required" {
		t.Errorf("refused fetch body: %s (%v)", rr.Body.String(), err)
	}

	// A Referer on another host, or none: not a place to send the post back
	// to, so the refusal falls through to the ordinary answer.
	for _, ref := range []string{"https://evil.example/order/form", "", "https://example.com/unmask/challenge/?_orig=%2Fx"} {
		hdr := map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"}
		if ref != "" {
			hdr["Referer"] = ref
		}
		_, rr = post("https://example.com/unmask/challenge/?_orig=%2Forder%2Fcheck", false, hdr)
		if rr.Code == http.StatusSeeOther || rr.Code == http.StatusTemporaryRedirect {
			t.Errorf("referer %q: status %d, must not redirect", ref, rr.Code)
		}
	}

	// A forced reason keeps its challenge even with a good _bvj: a trap, a
	// ban, a protected path, a custom rule, the rate path, an off-site _orig.
	for name, hdr := range map[string]map[string]string{
		"honeypot":  {"X-Honeypot-Hit": "1"},
		"banned":    {"X-Banned": "1"},
		"protected": {"X-Protected-Mode": "captcha"},
		"rule":      {"X-Unmask-Rule": "r1"},
		"bot":       {"X-JA4-Action": "bot"},
	} {
		_, rr = post("https://example.com/unmask/challenge/?_orig=%2Forder%2Fcheck", true, hdr)
		if rr.Code == http.StatusTemporaryRedirect || rr.Code == http.StatusSeeOther {
			t.Errorf("%s: status %d, a forced challenge must not be re-bound", name, rr.Code)
		}
	}
	_, rr = post("https://example.com/unmask/_rl/order/check", true, nav)
	if rr.Code == http.StatusTemporaryRedirect || rr.Code == http.StatusSeeOther {
		t.Errorf("rate path: status %d, must not be re-bound", rr.Code)
	}
	_, rr = post("https://example.com/unmask/challenge/?_orig=%2F%2Fevil.example%2F", true, nav)
	if rr.Code == http.StatusTemporaryRedirect {
		t.Errorf("off-site _orig: status %d, must not redirect", rr.Code)
	}

	// A GET is the page's business: the bounce page, as before.
	h := newRebindTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/?_orig=%2Forder%2Fform", nil)
	req.Host = "example.com"
	req.Header.Set("X-Real-IP", "203.0.113.5")
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Client-JA4", ja4)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.AddCookie(&http.Cookie{Name: "_bv", Value: "stale"})
	req.AddCookie(&http.Cookie{Name: "_bvj", Value: bvj})
	rr = httptest.NewRecorder()
	h.ServeChallengeOrJSON(rr, req)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Unmask-Mode") != "rebind" || !strings.Contains(rr.Body.String(), "/order/form") {
		t.Errorf("GET: status %d mode %q, want the bounce page", rr.Code, rr.Header().Get("X-Unmask-Mode"))
	}
}

// sameOriginReferer: the form's page on this host, as a local path; nothing
// for another host, a bare origin elsewhere, the challenge route, or junk.
func TestSameOriginReferer(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/unmask/challenge/", nil)
	req.Host = "example.com"
	for ref, want := range map[string]string{
		"https://example.com/order/form?step=2":  "/order/form?step=2",
		"https://EXAMPLE.com:443/":               "/",
		"http://example.com/a%20b":               "/a%20b",
		"https://evil.example/order/form":        "",
		"https://example.com.evil.example/":      "",
		"ftp://example.com/x":                    "",
		"https://example.com/unmask/challenge/?": "",
		"https://example.com/unmask/_rl/x":       "",
		"/relative":                              "",
		"":                                       "",
	} {
		req.Header.Set("Referer", ref)
		if got := sameOriginReferer(req, "/unmask"); got != want {
			t.Errorf("%q -> %q, want %q", ref, got, want)
		}
	}
}
