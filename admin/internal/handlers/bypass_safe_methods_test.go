package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Forward-auth agrees with the native render: a preset for files that are
// only ever fetched (here /robots.txt) passes GET / HEAD / OPTIONS only, and
// a POST to it is judged -- the protected rule on the same path then
// challenges it.  An operator's row passes every method.  A snippet from
// before the method header sends none, and the preset then passes every
// method, as it did.
func TestAuthCheckBypassPresetSafeMethods(t *testing.T) {
	cfg := settings.Settings{Nginx: settings.Nginx{
		BypassPaths: settings.BypassPathsConfig{
			Paths: []settings.BypassPath{{Path: `^/hooks/`}},
		},
		ProtectedPaths: settings.ProtectedPathsConfig{
			Paths: []settings.ProtectedPath{{Path: `^/robots\.txt$`}, {Path: `^/hooks/`}},
		},
	}}
	check := func(uri, method string, sendMethod bool) *http.Response {
		t.Helper()
		h := &Handler{}
		h.SetSettings(cfg)
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.Header.Set("X-Original-URI", uri)
		r.Header.Set("X-Original-IP", "203.0.113.50")
		r.Header.Set("X-Original-Host", "shop.example.com")
		if sendMethod {
			r.Header.Set("X-Original-Method", method)
		}
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
		w := httptest.NewRecorder()
		h.AuthCheck(w, r)
		return w.Result()
	}
	cases := []struct {
		name       string
		uri        string
		method     string
		sendMethod bool
		wantReason string // "" = must not be the bypass
	}{
		{"preset GET passes", "/robots.txt", "GET", true, "bypass:path"},
		{"preset HEAD passes", "/robots.txt", "HEAD", true, "bypass:path"},
		{"preset OPTIONS passes", "/robots.txt", "OPTIONS", true, "bypass:path"},
		{"preset POST is judged", "/robots.txt", "POST", true, ""},
		{"preset PUT is judged", "/robots.txt", "PUT", true, ""},
		{"no method header: as before", "/robots.txt", "", false, "bypass:path"},
		{"operator row POST passes", "/hooks/deploy", "POST", true, "bypass:path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := check(c.uri, c.method, c.sendMethod)
			reason := res.Header.Get("X-Unmask-Reason")
			if c.wantReason != "" {
				if reason != c.wantReason || res.StatusCode != http.StatusOK {
					t.Errorf("status %d reason %q, want 200 %q", res.StatusCode, reason, c.wantReason)
				}
				return
			}
			if reason == "bypass:path" || res.StatusCode == http.StatusOK {
				t.Errorf("status %d reason %q: a %s to a fetched-file preset must be judged (here: the protected rule's challenge)", res.StatusCode, reason, c.method)
			}
		})
	}
}
