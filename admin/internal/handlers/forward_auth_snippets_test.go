package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The distro matrix installs nginx + Apache but never Traefik (#203), so the
// only thing tying the shipped Traefik forward-auth snippet to reality is that
// /api/check keeps speaking the same contract: a verdict in X-Unmask-Action
// (pass|challenge|block), the matching 200/401/403 status, and X-Unmask-Reason
// — the headers the snippet forwards downstream and the status codes its
// redirect/block behavior relies on.  These tests pin both halves: the
// handler's response contract, and the snippet file that depends on it.

// driveAuthCheck runs the full AuthCheck handler against a forward-auth style
// request (X-Original-* headers, as nginx/Traefik send them) and returns
// the recorded response.  DB / BanMgr / RateLimiter stay nil — every decision
// helper tolerates that, and event recording is nil-safe.
func driveAuthCheck(t *testing.T, cfg settings.Settings, uri string) *http.Response {
	t.Helper()
	h := &Handler{}
	h.SetSettings(cfg)
	r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
	r.Header.Set("X-Original-URI", uri)
	r.Header.Set("X-Original-IP", "203.0.113.50") // TEST-NET-3, not loopback/bypass
	r.Header.Set("X-Original-Host", "shop.example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	w := httptest.NewRecorder()
	h.AuthCheck(w, r)
	return w.Result()
}

func TestAuthCheckForwardAuthContract(t *testing.T) {
	// A bypass path is a deterministic hard pass; a protected path is a
	// deterministic challenge (default chain mode).  Together they pin the two
	// statuses the forward-auth snippets branch on.
	passCfg := settings.Settings{Nginx: settings.Nginx{
		BypassPaths: settings.BypassPathsConfig{
			Paths: []settings.BypassPath{{Path: "/bypass-me"}},
		},
	}}
	challengeCfg := settings.Settings{Nginx: settings.Nginx{
		ProtectedPaths: settings.ProtectedPathsConfig{
			Paths: []settings.ProtectedPath{{Path: "/protected-area"}},
		},
	}}

	cases := []struct {
		name       string
		cfg        settings.Settings
		uri        string
		wantStatus int
		wantAction string
	}{
		{"bypass path -> pass/200", passCfg, "/bypass-me", http.StatusOK, "pass"},
		{"protected path -> challenge/401", challengeCfg, "/protected-area", http.StatusUnauthorized, "challenge"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := driveAuthCheck(t, c.cfg, c.uri)
			if res.StatusCode != c.wantStatus {
				t.Errorf("status = %d, want %d", res.StatusCode, c.wantStatus)
			}
			if got := res.Header.Get("X-Unmask-Action"); got != c.wantAction {
				t.Errorf("X-Unmask-Action = %q, want %q", got, c.wantAction)
			}
			// The reason is what dashboards / downstream services read; it must
			// always be populated so a blank header can't masquerade as a verdict.
			if res.Header.Get("X-Unmask-Reason") == "" {
				t.Error("X-Unmask-Reason is empty (forward-auth consumers expect a reason)")
			}
			// Verdicts must never be cached by an intermediary.
			if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
		})
	}
}

// repoSnippetsDir resolves the shipped snippets/ directory from this test's own
// source path (admin/internal/handlers -> repo root is three levels up), so it
// works regardless of the test working directory.
func repoSnippetsDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Join(filepath.Dir(self), "..", "..", "..", "snippets")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("snippets dir not found at %s (%v) — packaged-snippet lint skipped", dir, err)
	}
	return dir
}

func TestForwardAuthSnippetsMatchHandlerContract(t *testing.T) {
	dir := repoSnippetsDir(t)
	cases := []struct {
		file     string
		mustHave []string
	}{
		{"traefik-forward-auth.yml", []string{
			"/unmask/api/check", // forwardAuth address
			"X-Unmask-Action",   // authResponseHeaders
			"X-Unmask-Reason",   // authResponseHeaders
			"127.0.0.1:9477",    // admin service
		}},
	}
	for _, c := range cases {
		body, err := os.ReadFile(filepath.Join(dir, c.file))
		if err != nil {
			t.Errorf("read %s: %v", c.file, err)
			continue
		}
		text := string(body)
		for _, want := range c.mustHave {
			if !strings.Contains(text, want) {
				t.Errorf("%s: missing %q — forward-auth contract drift vs /api/check", c.file, want)
			}
		}
	}
}
