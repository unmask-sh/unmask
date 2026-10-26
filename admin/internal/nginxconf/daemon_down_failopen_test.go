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
	httpInc := renderWBA(t, false, "http.inc")

	t.Run("server_inc_scaffolding", func(t *testing.T) {
		for _, want := range []string{
			`set $unmask_orig_path "";`,
			`set $unmask_orig_args "";`,
		} {
			if !strings.Contains(server, want) {
				t.Errorf("server.inc missing init %q", want)
			}
		}
	})

	t.Run("failopen_mark_survives_internal_redirects", func(t *testing.T) {
		// nginx runs the server rewrite phase again on every internal
		// redirect.  A reset there wiped the mark as soon as the replayed
		// page went on to its index file or a try_files URI fallback: that
		// pass was gated again, sent back to the dead daemon, and the second
		// 502 surfaced raw.  The only set is the "1"; the empty default is a
		// map, which a set overrides for the rest of the request.
		if n := directives(server, "set $unmask_failopen"); n != 1 || !strings.Contains(server, `set $unmask_failopen "1";`) {
			t.Errorf("server.inc must set $unmask_failopen once, to \"1\" in @unmask_daemon_down (found %d sets)", n)
		}
		if !strings.Contains(httpInc, "map $remote_addr $unmask_failopen {\n    default \"\";\n}") {
			t.Error("http.inc must give $unmask_failopen its empty default as a map")
		}
	})

	t.Run("daemon_proxy_hooks", func(t *testing.T) {
		// The admin location and the machinery catch-all: both fail open.
		if got := strings.Count(server, "error_page 502 503 504 = @unmask_daemon_down;"); got != 2 {
			t.Errorf("the admin and /unmask/ proxies must hook 502/503/504 into @unmask_daemon_down, found %d", got)
		}
		// ...for nginx's own 502/504 only.  A 5xx the daemon sends is its
		// answer: intercepted, the webhook test's 502 + JSON reached the
		// settings page as the fail-open 503's text.  Both hooks carry the
		// off (written out, so a vhost-level "on" is not inherited); the ban
		// location keeps its own "on", checked below.
		for _, loc := range []string{"location ^~ /unmask/admin/ {", "location ^~ /unmask/ {"} {
			block := locationBlock(t, server, loc)
			if !strings.Contains(block, "proxy_intercept_errors off;") || strings.Contains(block, "proxy_intercept_errors on;") {
				t.Errorf("%s must pass the daemon's own 5xx through (proxy_intercept_errors off)", loc)
			}
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

// locationBlock returns the rendered block that opens with marker (a whole
// "location ... {" line) up to its closing brace at the start of a line, or
// fails the test if the block is absent.
func locationBlock(t *testing.T, conf, marker string) string {
	t.Helper()
	start := strings.Index(conf, marker)
	if start < 0 {
		t.Fatalf("rendered server.inc has no %q block", marker)
	}
	rest := conf[start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("%q block is not closed", marker)
	}
	return rest[:end]
}
