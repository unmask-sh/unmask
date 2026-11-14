package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// TestVisitorOrigURI: the page a challenge is served for comes from
// X-Original-URI when nginx routed the request here from that page -- the
// request line's URI as the client sent it -- and from the _orig arg on a
// direct hit or with no header.  Both of nginx's writers garble _orig: the
// classic rewrite ends it at the first '&' (nginx writes $request_uri there
// unescaped and appends the request's own args), and a module before 0.1.58
// left '%' unescaped, so a "%26" the visitor sent read back as '&'.
func TestVisitorOrigURI(t *testing.T) {
	const bp = "/unmask"
	for _, c := range []struct{ what, target, oru, uri, display string }{
		{"the classic rewrite: _orig ends at the first '&', the header has the query whole",
			"/unmask/challenge/?_orig=/s?a=1&b=2&a=1&b=2", "/s?a=1&b=2", "/s?a=1&b=2", "/s?a=1&b=2"},
		{"the module's redirect: an escaped '&' the visitor sent stays escaped",
			"/unmask/challenge/?_orig=/s%3Fq=a%2526b%26c=d", "/s?q=a%26b&c=d", "/s?q=a%26b&c=d", "/s?q=a&b&c=d"},
		{"a ban's rewrite carries no _orig: the header names the probed page",
			"/unmask/challenge/", "/wp-login.php?a=1&b=2", "/wp-login.php?a=1&b=2", "/wp-login.php?a=1&b=2"},
		{"the protected admin is a page like any other",
			"/unmask/challenge/?_orig=/unmask/admin/", "/unmask/admin/?tab=a&x=b", "/unmask/admin/?tab=a&x=b", "/unmask/admin/?tab=a&x=b"},
		{"a direct hit names itself in the header: _orig, decoded by the query parser",
			"/unmask/challenge/?_orig=%2Fpage%3Fx%3D1%26y%3D2", "/unmask/challenge/?_orig=%2Fpage%3Fx%3D1%26y%3D2", "/page?x=1&y=2", "/page?x=1&y=2"},
		{"no header (the Apache snippet's redirect): _orig",
			"/unmask/challenge/?_orig=%2Fp%3Fa%3D1", "", "/p?a=1", "/p?a=1"},
		{"a header naming one of unmask's endpoints, under a proxy that rewrote the prefix: _orig",
			"/unmask/challenge/?_orig=%2Fp", "/unmask/challenge/x", "/p", "/p"},
		{"a direct hit on the rate route is no page",
			"/unmask/_rl/x", "/unmask/_rl/x", "", ""},
		{"a header that is not a path is not read",
			"/unmask/challenge/?_orig=%2Fp", "https://evil.example/", "/p", "/p"},
	} {
		r := httptest.NewRequest(http.MethodGet, c.target, nil)
		if c.oru != "" {
			r.Header.Set("X-Original-URI", c.oru)
		}
		if got := visitorOrigURI(r, bp); got != c.uri {
			t.Errorf("%s: visitorOrigURI = %q, want %q", c.what, got, c.uri)
		}
		if got := visitorOrigPath(r, bp); got != c.display {
			t.Errorf("%s: visitorOrigPath = %q, want %q", c.what, got, c.display)
		}
	}
}

// TestProtectedMatchPathDecodes: the protected-path rules match the path as
// nginx's $uri holds it -- the query cut, the escapes decoded -- so a page
// asked for as "/unm%61sk/admin/" resolves the rule "/unmask/admin/" does,
// now that the URI arrives as the client sent it.
func TestProtectedMatchPathDecodes(t *testing.T) {
	for in, want := range map[string]string{
		"/unmask/admin/?x=1": "/unmask/admin/",
		"/unm%61sk/admin/":   "/unmask/admin/",
		"/a%2Fb?c=%2F":       "/a/b",
		"/bad%zz":            "/bad%zz", // not an escape: kept as it is
	} {
		if got := protectedMatchPath(in); got != want {
			t.Errorf("protectedMatchPath(%q) = %q, want %q", in, got, want)
		}
	}
	n := faAdminCfg().Nginx
	plain, escaped := protectedModeForOrig(n, "", "/unmask/admin/"), protectedModeForOrig(n, "", "/unm%61sk/admin/?x=1")
	if !nginxconf.ModeEndsInCaptcha(plain) || escaped != plain {
		t.Errorf("protected mode: %q for the path, %q for it escaped; want the same captcha-ending mode", plain, escaped)
	}
}

// TestServeChallenge_BreakerPassthroughReturnsToTheURIAsSent: the visitor
// the breaker lets through goes back to the page as the client asked for it,
// not to the version _orig carried.
func TestServeChallenge_BreakerPassthroughReturnsToTheURIAsSent(t *testing.T) {
	h := breakerHandler(t)
	for _, c := range []struct{ what, target, oru, want string }{
		{"the classic rewrite's _orig ends at the first '&'",
			"/unmask/challenge/?_orig=/s?a=1&b=2&a=1&b=2", "/s?a=1&b=2", "/s?a=1&b=2"},
		{"an escaped '&' stays escaped",
			"/unmask/challenge/?_orig=/s%3Fq=a%2526b%26c=d", "/s?q=a%26b&c=d", "/s?q=a%26b&c=d"},
		{"an off-site header is never echoed",
			"/unmask/challenge/", "//evil.example/", "/"},
	} {
		req := httptest.NewRequest(http.MethodGet, c.target, nil)
		req.Header.Set("X-Real-IP", "203.0.113.6")
		req.Header.Set("X-Original-URI", c.oru)
		w := httptest.NewRecorder()
		h.ServeChallenge(w, req)
		if got := w.Result().Header.Get("Location"); got != c.want {
			t.Errorf("%s: Location = %q, want %q", c.what, got, c.want)
		}
	}
}
