package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
)

// requestHost names the host the way nginx's $host does -- lowercased, no
// port, an IPv6 literal in its brackets -- because the plugin folds $host
// into every signature and seed it checks, and the daemon has to sign for
// the same name.  It took the brackets off: a pass issued for a visitor who
// reached the site by its IPv6 address was signed for "2001:db8::1", the
// plugin checked it against "[2001:db8::1]", and nothing ever verified.
func TestRequestHostIsNginxsHost(t *testing.T) {
	for _, c := range []struct{ header, value, want string }{
		// What the proxy sends: $host itself.
		{"X-Original-Host", "example.com", "example.com"},
		{"X-Original-Host", "[2001:db8::1]", "[2001:db8::1]"},
		{"X-Original-Host", "[::1]", "[::1]"},
		{"X-Original-Host", "192.0.2.7", "192.0.2.7"},
		// The fallbacks carry the Host header as the client wrote it.
		{"X-Forwarded-Host", "Example.COM:8443", "example.com"},
		{"X-Forwarded-Host", "[2001:DB8::1]:443", "[2001:db8::1]"},
		{"Host", "[2001:db8::a]:8443", "[2001:db8::a]"},
		{"Host", "[::1]", "[::1]"},
		{"Host", "192.0.2.7:8080", "192.0.2.7"},
		{"Host", "example.com", "example.com"},
		// No closing bracket is no host nginx passes on; left as written.
		{"Host", "[2001:db8::1", "[2001:db8::1"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = ""
		if c.header == "Host" {
			r.Host = c.value
		} else {
			r.Header.Set(c.header, c.value)
		}
		if got := requestHost(r); got != c.want {
			t.Errorf("%s: %q -> %q, want %q", c.header, c.value, got, c.want)
		}
	}

	// The pass the daemon issues for such a request is the one the plugin
	// verifies: signed for $host as nginx has it.
	const secret, ip, nginxHost = "test-secret", "198.51.100.7", "[2001:db8::1]"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Original-Host", nginxHost)
	pass := cookies.IssueValue(secret, ip, requestHost(r), "captcha")
	if !cookies.Verify(pass, secret, ip, nginxHost, 604800, 1209600, 18) {
		t.Errorf("a pass issued for requestHost %q does not verify under nginx's $host %q", requestHost(r), nginxHost)
	}
	seed := cookies.PowSeed(secret, ip, requestHost(r), 1700000000)
	if want := cookies.PowSeed(secret, ip, nginxHost, 1700000000); seed != want {
		t.Errorf("the seed for requestHost %q is not the one the plugin derives for $host %q", requestHost(r), nginxHost)
	}
}

// The page a refused post is sent back to is the Referer when it names the
// requested host, and a Referer writes an IPv6 literal the way a URL does.
func TestSameOriginRefererOnAnIPv6Host(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://[2001:db8::1]/unmask/challenge/", nil)
	req.Host = "[2001:db8::1]:8443"
	for ref, want := range map[string]string{
		"https://[2001:db8::1]:8443/order/form?step=2": "/order/form?step=2",
		"https://[2001:DB8::1]/":                       "/",
		"https://[2001:db8::2]/order/form":             "",
		"https://2001.example/order/form":              "",
	} {
		req.Header.Set("Referer", ref)
		if got := sameOriginReferer(req, "/unmask"); got != want {
			t.Errorf("%q -> %q, want %q", ref, got, want)
		}
	}
}
