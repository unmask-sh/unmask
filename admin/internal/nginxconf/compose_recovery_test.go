package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// renderRate renders the nginx snippets for a config whose only rate-limit
// zones are `zones`, returning the requested file's content.  A "deny" zone
// flips the render into compose mode (protect.inc runs limit_req in dry-run and
// the plugin's ACCESS-phase handler composes the rate + captcha decision);
// without one the render stays on the classic error_page-429 + rewrite flow.
func renderRate(t *testing.T, zones []settings.RateZone, file string) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.RateLimit.Zones = zones
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return string(b)
}

func denyZones() []settings.RateZone {
	return []settings.RateZone{{
		Name: "deny_z", RequestsPerMin: 5, Burst: 2,
		PathPatterns: []string{"/deny/"}, ChallengeMode: settings.RateChallengeDeny,
	}}
}

func challengeZones() []settings.RateZone {
	return []settings.RateZone{{
		Name: "chal_z", RequestsPerMin: 5, Burst: 2,
		PathPatterns: []string{"/chal/"}, ChallengeMode: settings.RateChallengeCaptchaOnly,
	}}
}

// TestComposeFailOpenRecovery: when a deny zone exists the render emits compose
// mode.  Its fail-open replay can't reuse the classic save: the ACCESS-phase
// internal_redirect restarts the phase engine and re-runs server.inc's
// SERVER_REWRITE reset of $unmask_orig_path (the classic `rewrite ... last`
// jumps to FIND_CONFIG and skips it).  So @unmask_daemon_down recovers the
// original from what the handler carried in the redirect (the _orig arg /
// the /unmask/_rl URI suffix), split into a clean path + args by http.inc maps.
// This guards every moving part of that recovery, including the security gate.
func TestComposeFailOpenRecovery(t *testing.T) {
	httpInc := renderRate(t, denyZones(), "http.inc")
	server := renderRate(t, denyZones(), "server.inc")
	protect := renderRate(t, denyZones(), "protect.inc")

	t.Run("http_inc_recovery_maps", func(t *testing.T) {
		for _, want := range []string{
			"map $unmask_co_orig $unmask_orig_arg_path {",
			"map $unmask_co_orig $unmask_orig_arg_args {",
			"map $unmask_co_uri $unmask_rl_orig {",
		} {
			if !strings.Contains(httpInc, want) {
				t.Errorf("http.inc (compose) missing recovery map %q", want)
			}
		}
	})

	t.Run("recovery_is_compose_gated", func(t *testing.T) {
		// SECURITY: the carried _orig / _uri are exposed to the recovery ONLY
		// through $unmask_compose, which only protect.inc's compose branch sets
		// (and which survives to @unmask_daemon_down -- nothing resets it at
		// server scope).  A server-scope ban rewrite and a direct /unmask/_rl
		// hit both leave it unset, so a banned client can't smuggle a crafted
		// ?_orig=/wherever past the "bans hold during an outage" contract.
		for _, want := range []string{
			"map $unmask_compose $unmask_co_orig {",
			"map $unmask_compose $unmask_co_uri {",
		} {
			if !strings.Contains(httpInc, want) {
				t.Errorf("http.inc (compose) missing the $unmask_compose gate %q", want)
			}
		}
		// The split maps must key off the GATED variable, never $arg__orig /
		// $uri directly -- otherwise the gate is bypassable.
		if strings.Contains(httpInc, "map $arg__orig $unmask_orig_arg_path") {
			t.Error("recovery path map keys on $arg__orig directly -- the compose gate is bypassed")
		}
		if strings.Contains(httpInc, "map $uri $unmask_rl_orig") {
			t.Error("recovery rl map keys on $uri directly -- the compose gate is bypassed")
		}
	})

	t.Run("server_inc_recovery_blocks", func(t *testing.T) {
		for _, want := range []string{
			"set $unmask_orig_path $unmask_orig_arg_path;",
			"set $unmask_orig_args $unmask_orig_arg_args;",
			"set $unmask_orig_path $unmask_rl_orig;",
		} {
			if !strings.Contains(server, want) {
				t.Errorf("server.inc (compose) missing recovery assignment %q", want)
			}
		}
		// Recovery fires only while the saved original is still empty, so a
		// classic-style save (if any) is never overwritten.
		if !strings.Contains(server, `if ($unmask_orig_path = "") {`) {
			t.Error("server.inc (compose) recovery must be guarded by an empty-orig check")
		}
	})

	t.Run("protect_inc_compose_branch", func(t *testing.T) {
		for _, want := range []string{
			"limit_req_dry_run on;",
			"set $unmask_compose 1;",
		} {
			if !strings.Contains(protect, want) {
				t.Errorf("protect.inc (compose) missing %q", want)
			}
		}
		// The dead REWRITE-phase save (cleared by SERVER_REWRITE before the
		// replay) must be gone, and the classic 429 gate must not appear.
		if strings.Contains(protect, "set $unmask_orig_path $uri;") {
			t.Error("protect.inc (compose) still saves $unmask_orig_path -- the save is cleared before the replay, so it must be dropped")
		}
		if strings.Contains(protect, "error_page 429") {
			t.Error("protect.inc (compose) must not arm the classic error_page-429 gate")
		}
	})
}

// TestClassicConfigUnaffected: a config with NO deny zone keeps the classic
// flow byte-for-byte -- none of the compose recovery machinery is emitted, and
// protect.inc keeps its REWRITE-phase challenge gate (which saves the original
// and survives via `rewrite ... last`).
func TestClassicConfigUnaffected(t *testing.T) {
	httpInc := renderRate(t, challengeZones(), "http.inc")
	server := renderRate(t, challengeZones(), "server.inc")
	protect := renderRate(t, challengeZones(), "protect.inc")

	t.Run("no_compose_recovery", func(t *testing.T) {
		for _, bad := range []string{"$unmask_co_orig", "$unmask_rl_orig", "$unmask_orig_arg_path"} {
			if strings.Contains(httpInc, bad) {
				t.Errorf("http.inc (classic) must not emit compose var %q", bad)
			}
			if strings.Contains(server, bad) {
				t.Errorf("server.inc (classic) must not emit compose var %q", bad)
			}
		}
		if strings.Contains(protect, "set $unmask_compose 1;") {
			t.Error("protect.inc (classic) must not set $unmask_compose")
		}
		if strings.Contains(protect, "limit_req_dry_run on;") {
			t.Error("protect.inc (classic) must not run limit_req in dry-run")
		}
	})

	t.Run("classic_gate_present", func(t *testing.T) {
		for _, want := range []string{
			`if ($unmask_gate = "1:") {`,
			"set $unmask_orig_path $uri;",
			"error_page 429 = @unmask_rate_challenge;",
		} {
			if !strings.Contains(protect, want) {
				t.Errorf("protect.inc (classic) missing gate piece %q", want)
			}
		}
	})
}
