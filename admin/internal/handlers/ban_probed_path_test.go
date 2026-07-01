package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBanProbedOrigPath locks the native ban-challenge URL recovery: the probed
// path is taken from X-Original-URI only when it is a real off-basePath path, so
// a direct challenge request (which carries /unmask/challenge/... here) does not
// poison the hunt URL column.
func TestBanProbedOrigPath(t *testing.T) {
	const base = "/unmask"
	cases := []struct {
		name, header, want string
	}{
		{"probed php shell", "/w.php", "/w.php"},
		{"probed path with query", "/a.php?id=1", "/a.php?id=1"},
		{"dotfile probe", "/.env", "/.env"},
		{"direct challenge URL rejected", "/unmask/challenge/", ""},
		{"challenge asset rejected", "/unmask/static/app.js", ""},
		{"empty header", "", ""},
		{"absolute URL (no leading slash) rejected", "https://evil.test/x", ""},
		{"non-slash rejected", "w.php", ""},
		{"basePath prefix without slash is a real path", "/unmasked", "/unmasked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
			if c.header != "" {
				req.Header.Set("X-Original-URI", c.header)
			}
			if got := banProbedOrigPath(req, base); got != c.want {
				t.Errorf("banProbedOrigPath(%q) = %q, want %q", c.header, got, c.want)
			}
		})
	}
}
