package nginxconf

import (
	"strings"
	"testing"
)

// TestDaemonDownFailOpenRendered: native mode must fail open automatically
// when the admin daemon is unreachable — the rendered config replays the
// visitor's original request instead of surfacing the proxy's 502, with no
// operator-supplied named location required.  Guards the moving parts:
// the variable scaffolding, the error_page hooks on every daemon proxy
// location, the replay named location, and the gate suppression that keeps
// the replay from looping back into the dead proxy.
func TestDaemonDownFailOpenRendered(t *testing.T) {
	server := renderWBA(t, false, "server.inc")
	protect := renderWBA(t, false, "protect.inc")

	t.Run("server_inc_scaffolding", func(t *testing.T) {
		for _, want := range []string{
			`set $unmask_failopen  "";`,
			`set $unmask_orig_path "";`,
			`set $unmask_orig_args "";`,
		} {
			if !strings.Contains(server, want) {
				t.Errorf("server.inc missing init %q", want)
			}
		}
	})

	t.Run("daemon_proxy_hooks", func(t *testing.T) {
		// The admin location and the machinery catch-all: both fail open.
		if got := strings.Count(server, "error_page 502 503 504 = @unmask_daemon_down;"); got != 2 {
			t.Errorf("the admin and /unmask/ proxies must hook 502/503/504 into @unmask_daemon_down, found %d", got)
		}
		if !strings.Contains(server, "proxy_intercept_errors on;") {
			t.Error("daemon proxy locations must set proxy_intercept_errors on")
		}
	})

	t.Run("ban_location_fails_closed", func(t *testing.T) {
		// nginx keeps the FIRST error_page written for a status code, so the
		// ban page's fail-closed hook only works if no fail-open hook precedes
		// it in the same block.  Until 0.1.44 the proxy template emitted the
		// fail-open hook first, and a banned client that arrived during a
		// daemon restart got @unmask_daemon_down's 503 (nothing to replay)
		// instead of the 403 -- the one 5xx the restart-race e2e kept finding.
		start := strings.Index(server, "location ^~ /unmask/_ban {")
		if start < 0 {
			t.Fatal("server.inc has no /unmask/_ban location")
		}
		end := strings.Index(server[start:], "\n}")
		if end < 0 {
			t.Fatal("/unmask/_ban location does not close")
		}
		block := server[start : start+end]
		if !strings.Contains(block, "error_page 502 503 504 = @unmask_ban_deny_down;") || !strings.Contains(block, "proxy_intercept_errors on;") {
			t.Error("/unmask/_ban must intercept 502/503/504 into @unmask_ban_deny_down")
		}
		if strings.Contains(block, "= @unmask_daemon_down;") {
			t.Error("/unmask/_ban must not carry the fail-open hook: written first, it would shadow the fail-closed one")
		}
		if !strings.Contains(server, "location @unmask_ban_deny_down {\n    return 403;") {
			t.Error("@unmask_ban_deny_down must answer a bare 403")
		}
	})

	t.Run("replay_location", func(t *testing.T) {
		for _, want := range []string{
			"location @unmask_daemon_down {",
			`set $unmask_failopen "1";`,
			// replay is allowed only for originals outside /unmask/ — an
			// /unmask/* original would re-enter the dead proxy (error_page
			// does not recurse) and surface a raw 502.
			`if ($unmask_orig_path ~ "^/(?!unmask(/|$))") {`,
			"return 503 ",
			"set $args $unmask_orig_args;",
			"rewrite ^ $unmask_orig_path last;",
		} {
			if !strings.Contains(server, want) {
				t.Errorf("server.inc missing replay piece %q", want)
			}
		}
	})

	t.Run("rate_challenge_loop_guard", func(t *testing.T) {
		// A replayed request can hit limit_req again; the named location must
		// answer 429 instead of rewriting back into the dead daemon.
		if !strings.Contains(server, `if ($unmask_failopen = "1") {`) {
			t.Error("@unmask_rate_challenge must short-circuit replayed requests")
		}
		if !strings.Contains(server, "return 429 ") {
			t.Error("@unmask_rate_challenge replay branch must answer a plain 429")
		}
	})

	t.Run("gate_saves_orig_and_suppresses_replay", func(t *testing.T) {
		for _, want := range []string{
			`set $unmask_gate "${final_challenge}:${unmask_failopen}";`,
			`if ($unmask_gate = "1:") {`,
			"set $unmask_orig_path $uri;",
			"set $unmask_orig_args $args;",
		} {
			if !strings.Contains(protect, want) {
				t.Errorf("protect.inc missing gate piece %q", want)
			}
		}
	})
}
