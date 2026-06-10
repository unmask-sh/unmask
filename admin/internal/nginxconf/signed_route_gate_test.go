package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSignedRouteGatedByWebBotAuth: the Web Bot Auth (signed-agent) branch in
// server.inc must be rendered ONLY when WBA is enabled.  With it disabled (the
// default), a request that merely carries a Signature-Input header must NOT be
// re-routed through the signed-route -- otherwise a proxied path the daemon
// passes (e.g. /rss/ on the bypass list) lands on the signed-route's
// `try_files ... =404` and returns 404 instead of the proxied content.
func TestSignedRouteGatedByWebBotAuth(t *testing.T) {
	render := func(t *testing.T, enabled bool) string {
		t.Helper()
		dir := t.TempDir()
		conf := filepath.Join(dir, "nginx.conf")
		if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		var s settings.Settings
		s.Nginx.OutputDir = dir
		s.Nginx.ConfPath = conf
		s.Nginx.WebBotAuth.Enabled = enabled
		if err := Render(s, dir, "test"); err != nil {
			t.Fatalf("Render: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "server.inc"))
		if err != nil {
			t.Fatalf("read server.inc: %v", err)
		}
		return string(b)
	}

	t.Run("disabled_omits_signed_route", func(t *testing.T) {
		out := render(t, false)
		if strings.Contains(out, "_signed_route") || strings.Contains(out, "_signed_verify") {
			t.Errorf("server.inc must omit the signed-agent branch when Web Bot Auth is " +
				"disabled, so a Signature-Input request is never re-routed to the " +
				"try_files=404 path")
		}
	})

	t.Run("enabled_emits_signed_route_with_failopen", func(t *testing.T) {
		out := render(t, true)
		if !strings.Contains(out, "location ^~ /_unmask/_signed_route/") {
			t.Fatalf("server.inc must contain the signed-route block when Web Bot Auth is enabled")
		}
		// The daemon-error fail-open must survive: 5xx degrades to the normal flow.
		if !strings.Contains(out, "error_page 401 403 500 502 503 504 = @unmask_signed_fallback") {
			t.Errorf("signed-route must keep the 401/403 + 5xx fail-open error_page")
		}
	})
}
