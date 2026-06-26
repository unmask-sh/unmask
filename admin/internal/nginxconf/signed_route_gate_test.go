package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// renderWBA renders all snippets with Web Bot Auth on/off and returns the
// requested output file's content.
func renderWBA(t *testing.T, enabled bool, file string) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.Nginx.AdvancedEnabled = enabled // master gate: WebBotAuthActive() needs both
	s.Nginx.WebBotAuth.Enabled = enabled
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return string(b)
}

// TestSignedRouteGatedByWebBotAuth: the Web Bot Auth (signed-agent) machinery
// must be rendered ONLY when WBA is enabled.  With it disabled (the default),
// a request that merely carries a Signature-Input header must behave exactly
// like an unsigned one — no detour, no extra maps, the plain $final_challenge
// decision in protect.inc.
func TestSignedRouteGatedByWebBotAuth(t *testing.T) {
	t.Run("disabled_omits_everything", func(t *testing.T) {
		for _, f := range []string{"server.inc", "http.inc", "protect.inc"} {
			out := renderWBA(t, false, f)
			if strings.Contains(out, "_signed_route") || strings.Contains(out, "_signed_verify") ||
				strings.Contains(out, "unmask_signed_gate") || strings.Contains(out, "final_challenge_eff") {
				t.Errorf("%s must omit all signed-agent machinery when Web Bot Auth is disabled", f)
			}
		}
		if out := renderWBA(t, false, "protect.inc"); !strings.Contains(out, `set $unmask_gate "${final_challenge}:${unmask_failopen}";`) {
			t.Errorf("protect.inc must keep the plain $final_challenge decision when WBA is disabled")
		}
	})

	t.Run("enabled_server_inc_shape", func(t *testing.T) {
		out := renderWBA(t, true, "server.inc")
		// Gate fires only via the composed map (signed AND would-challenge AND
		// not an unmask mount) — never on the raw header variable.
		if !strings.Contains(out, `if ($unmask_signed_gate = "1")`) {
			t.Fatalf("server.inc must gate the signed-route on $unmask_signed_gate")
		}
		if strings.Contains(out, `if ($unmask_has_signed_agent`) {
			t.Errorf("server.inc must not re-route on the raw header variable (subrequest hijack / bypass-path detour)")
		}
		// Every auth outcome converges on the continue location; the route must
		// never serve content itself (try_files $uri ... =404 404'd proxy sites).
		if !strings.Contains(out, "error_page 401 403 500 502 503 504 = @unmask_signed_continue") {
			t.Errorf("signed-route must catch 401/403 + 5xx into @unmask_signed_continue")
		}
		if !strings.Contains(out, "try_files /__unmask_signed_continue__ @unmask_signed_continue") {
			t.Errorf("signed-route success path must re-enter via the sentinel try_files")
		}
		// The verify subrequest must hit the admin route that actually exists
		// (= {base}/api/check, same handler forward-auth uses).  The original
		// template proxied to a phantom /_unmask/check and every signed
		// request 404'd at the daemon.
		if !strings.Contains(out, "proxy_pass http://unmask/unmask/api/check;") {
			t.Errorf("signed-verify subrequest must proxy to the real /unmask/api/check endpoint")
		}
		if strings.Contains(out, "try_files $uri") || strings.Contains(out, "=404") {
			t.Errorf("signed-route must not serve the URI off the filesystem (=404 on proxy sites)")
		}
		// Ban stays terminal: the ban if-blocks must precede the signed gate.
		ban := strings.Index(out, "$unmask_ban_action_effective")
		gate := strings.Index(out, `if ($unmask_signed_gate`)
		if ban < 0 || gate < 0 || ban > gate {
			t.Errorf("ban enforcement must run before the signed-route gate (ban=%d gate=%d)", ban, gate)
		}
	})

	t.Run("enabled_http_inc_maps", func(t *testing.T) {
		out := renderWBA(t, true, "http.inc")
		for _, want := range []string{
			"map $uri $unmask_uri_is_unmask",
			`map "$unmask_has_signed_agent:$unmask_uri_is_unmask:$final_challenge" $unmask_signed_gate`,
			"map $unmask_signed_action $unmask_signed_verified",
			// PAT off → the combined map reads the signed flag + a literal 0.
			`map "$unmask_signed_verified:0" $unmask_verified`,
			`map "$final_challenge:$unmask_verified" $final_challenge_eff`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("http.inc missing %q", want)
			}
		}
		// The veto-pass maps must be volatile: the auth subrequest re-runs
		// server-scope rewrites, so a value cached on the main request would
		// hijack the verify subrequest away from the daemon.
		if got := strings.Count(out, "volatile;"); got < 5 {
			t.Errorf("the veto-pass maps must all be volatile, found %d", got)
		}
	})

	t.Run("enabled_protect_inc_uses_eff", func(t *testing.T) {
		out := renderWBA(t, true, "protect.inc")
		if !strings.Contains(out, `set $unmask_gate "${final_challenge_eff}:${unmask_failopen}";`) {
			t.Errorf("protect.inc must enforce $final_challenge_eff when WBA is enabled")
		}
		if strings.Contains(out, `set $unmask_gate "${final_challenge}:${unmask_failopen}";`) {
			t.Errorf("protect.inc must not also enforce the raw $final_challenge when WBA is enabled")
		}
	})
}

// renderPP renders all snippets with Privacy Pass on/off and returns the
// requested output file's content.
func renderPP(t *testing.T, enabled bool, file string) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.Nginx.AdvancedEnabled = enabled // master gate: PrivacyPassActive() needs both
	s.Nginx.PrivacyPass.Enabled = enabled
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return string(b)
}

// TestPATRouteGatedByPrivacyPass: the native Privacy Pass (PAT) detour/verify
// machinery — mirroring the Web Bot Auth signed-route — must render ONLY when
// Privacy Pass is enabled, and stay on the same fail-safe shape (gate via the
// composed map, every outcome converges on @unmask_pat_continue, verify hits
// the real admin endpoint, ban stays terminal).
func TestPATRouteGatedByPrivacyPass(t *testing.T) {
	t.Run("disabled_omits_everything", func(t *testing.T) {
		for _, f := range []string{"server.inc", "http.inc", "protect.inc"} {
			out := renderPP(t, false, f)
			if strings.Contains(out, "_pat_route") || strings.Contains(out, "_pat_verify") ||
				strings.Contains(out, "unmask_pat_gate") || strings.Contains(out, "unmask_has_pat") {
				t.Errorf("%s must omit all PAT machinery when Privacy Pass is disabled", f)
			}
		}
		if out := renderPP(t, false, "protect.inc"); !strings.Contains(out, `set $unmask_gate "${final_challenge}:${unmask_failopen}";`) {
			t.Errorf("protect.inc must keep the plain $final_challenge decision when PAT is disabled")
		}
	})

	t.Run("enabled_server_inc_shape", func(t *testing.T) {
		out := renderPP(t, true, "server.inc")
		if !strings.Contains(out, `if ($unmask_pat_gate = "1")`) {
			t.Fatalf("server.inc must gate the PAT route on $unmask_pat_gate")
		}
		if !strings.Contains(out, "error_page 401 403 500 502 503 504 = @unmask_pat_continue") {
			t.Errorf("PAT route must catch 401/403 + 5xx into @unmask_pat_continue")
		}
		if !strings.Contains(out, "try_files /__unmask_pat_continue__ @unmask_pat_continue") {
			t.Errorf("PAT route success path must re-enter via the sentinel try_files")
		}
		if !strings.Contains(out, "proxy_pass http://unmask/unmask/api/check;") {
			t.Errorf("PAT-verify subrequest must proxy to the real /unmask/api/check endpoint")
		}
		if !strings.Contains(out, "proxy_set_header Authorization     $http_authorization;") {
			t.Errorf("PAT-verify must forward the PrivateToken Authorization header")
		}
		if strings.Contains(out, "try_files $uri") {
			t.Errorf("PAT route must not serve the URI off the filesystem (=404 on proxy sites)")
		}
		// Ban stays terminal: the ban if-blocks must precede the PAT gate.
		ban := strings.Index(out, "$unmask_ban_action_effective")
		gate := strings.Index(out, `if ($unmask_pat_gate`)
		if ban < 0 || gate < 0 || ban > gate {
			t.Errorf("ban enforcement must run before the PAT gate (ban=%d gate=%d)", ban, gate)
		}
	})

	t.Run("enabled_http_inc_maps", func(t *testing.T) {
		out := renderPP(t, true, "http.inc")
		for _, want := range []string{
			"map $uri $unmask_uri_is_unmask",
			"map $http_authorization $unmask_has_pat",
			`map "$unmask_has_pat:$unmask_uri_is_unmask:$final_challenge" $unmask_pat_gate`,
			"map $unmask_pat_action $unmask_pat_verified",
			// WBA off → the combined map reads a literal 0 + the pat flag.
			`map "0:$unmask_pat_verified" $unmask_verified`,
			`map "$final_challenge:$unmask_verified" $final_challenge_eff`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("http.inc missing %q", want)
			}
		}
		// A PAT-only render must not reference the WBA signed-agent variables.
		if strings.Contains(out, "unmask_signed") {
			t.Errorf("PAT-only http.inc must not reference signed-agent vars")
		}
	})

	t.Run("enabled_protect_inc_uses_eff", func(t *testing.T) {
		out := renderPP(t, true, "protect.inc")
		if !strings.Contains(out, `set $unmask_gate "${final_challenge_eff}:${unmask_failopen}";`) {
			t.Errorf("protect.inc must enforce $final_challenge_eff when PAT is enabled")
		}
	})
}

// TestVetoPassCombinedMap: with BOTH Web Bot Auth and Privacy Pass on, the
// shared $unmask_verified map reads both verified flags and both detours render.
func TestVetoPassCombinedMap(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.Nginx.AdvancedEnabled = true
	s.Nginx.WebBotAuth.Enabled = true
	s.Nginx.PrivacyPass.Enabled = true
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	httpInc, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(httpInc), `map "$unmask_signed_verified:$unmask_pat_verified" $unmask_verified`) {
		t.Errorf("combined $unmask_verified must read both signed + pat verified flags")
	}
	serverInc, err := os.ReadFile(filepath.Join(dir, "server.inc"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(serverInc), "_signed_route") || !strings.Contains(string(serverInc), "_pat_route") {
		t.Errorf("both detours must render when both features are on")
	}
}

// TestAdvancedMasterGatesBothFeatures: the advanced master switch is an AND
// gate.  With AdvancedEnabled=false but BOTH per-feature Enabled flags true,
// NO signed-route / PAT machinery may render -- "off" means off, not just
// hidden in the UI.  This is the render-side guarantee behind the master toggle.
func TestAdvancedMasterGatesBothFeatures(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.Nginx.AdvancedEnabled = false // master OFF...
	s.Nginx.WebBotAuth.Enabled = true
	s.Nginx.PrivacyPass.Enabled = true // ...even though both features are "enabled"
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, f := range []string{"server.inc", "http.inc", "protect.inc"} {
		out, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, marker := range []string{"_signed_route", "_signed_verify", "_pat_route", "_pat_verify", "unmask_signed_gate", "unmask_pat_gate", "unmask_verified"} {
			if strings.Contains(string(out), marker) {
				t.Errorf("%s must omit %q when the advanced master switch is off", f, marker)
			}
		}
	}
}
