package nginxconf

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// moduleDirectives are the directives only the module understands: an http.inc
// naming one of them while the module is not loaded is an nginx that does not
// start ("unknown directive").
var moduleDirectives = []string{
	"unmask_bv_secret", "unmask_bv_pow_valid_seconds", "unmask_bv_captcha_valid_seconds",
	"unmask_bv_pow_difficulty", "unmask_ban_file",
}

// moduleVariables are the variables only the module computes that the
// templates read.  Without the module nothing defines them, and a map keyed
// on one is an nginx that does not start ("unknown variable").
var moduleVariables = []string{
	"client_ja4", "unmask_bv_kind", "unmask_banned", "unmask_ban_action", "unmask_has_signed_agent",
	"unmask_client_net",
}

// renderFiles renders s into a scratch dir -- carrying the fail-safe marker
// when degraded -- and returns the dir and the rendered files by name.
func renderFiles(t *testing.T, degraded bool, mutate func(*settings.Settings)) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	if degraded {
		if err := os.WriteFile(filepath.Join(dir, FailsafeMarker),
			[]byte("native wiring stripped by place-module fail-safe\nreason: no bundled module for host nginx 1.99.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	renderInto(t, dir, "test", mutate)
	files := map[string]string{}
	for _, name := range []string{"http.inc", "server.inc", "protect.inc", "upstream.conf", "forward-auth-lbtrust.conf"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		files[name] = string(b)
	}
	return dir, files
}

// withLogAndBans: the common native install -- the access log feeding the
// daemon, a ban list -- so the directives and lines a degraded render must
// keep or drop are all there to be checked.
func withLogAndBans(s *settings.Settings) {
	s.NginxLog.Enabled = true
	s.NginxLog.SocketPath = "/run/unmask/log.sock"
	s.Nginx.Honeypot.BanFilePath = "/var/lib/unmask/banned.txt"
}

// The fail-safe marker in the output dir means the module is not loaded.
// The render then leaves out everything only the module can act on, keeps
// what gets the operator to the admin UI, and says so at the top of every
// file.  Without this a host whose vhost includes server.inc (as the README
// says to) could not start nginx at all after the fail-safe stripped http.inc:
// server.inc's access_log names the log format http.inc declares.
func TestDegradedRenderLeavesTheModuleOut(t *testing.T) {
	_, deg := renderFiles(t, true, withLogAndBans)
	_, full := renderFiles(t, false, withLogAndBans)

	t.Run("http_inc", func(t *testing.T) {
		inc := deg["http.inc"]
		for _, d := range moduleDirectives {
			if n := directives(inc, d); n != 0 {
				t.Errorf("degraded http.inc carries the module directive %s (%d)", d, n)
			}
		}
		for _, v := range moduleVariables {
			if !strings.Contains(inc, "map \"\" $"+v+" ") {
				t.Errorf("degraded http.inc does not define $%s as an empty map", v)
			}
		}
		if !strings.Contains(inc, "NATIVE FAIL-SAFE ACTIVE") || !strings.Contains(inc, "unmask doctor") {
			t.Error("degraded http.inc has no banner naming the fail-safe and `unmask doctor`")
		}
		// What every install needs from http.inc stays: the log format
		// server.inc's access_log names, and the maps the proxy headers read.
		for _, want := range []string{"log_format unmask_minimal ", "map $unmask_lb_ja4_or_sentinel $effective_ja4 {", " rv="} {
			if !strings.Contains(inc, want) {
				t.Errorf("degraded http.inc lost %q", want)
			}
		}
	})

	t.Run("full_render_unchanged", func(t *testing.T) {
		inc := full["http.inc"]
		for _, d := range moduleDirectives {
			if n := directives(inc, d); n != 1 {
				t.Errorf("full http.inc: %s appears %d times, want 1", d, n)
			}
		}
		// The module defines these; a map of the same name beside it would
		// be a duplicate-variable error at load.
		for _, v := range moduleVariables {
			if strings.Contains(inc, "map \"\" $"+v+" ") {
				t.Errorf("full http.inc defines the module's $%s as a map", v)
			}
		}
		for _, f := range []string{"http.inc", "server.inc", "protect.inc"} {
			if strings.Contains(full[f], "FAIL-SAFE") {
				t.Errorf("full %s mentions the fail-safe", f)
			}
		}
	})

	t.Run("protect_inc_inert", func(t *testing.T) {
		inc := deg["protect.inc"]
		for _, bad := range []string{"limit_req", "$unmask_gate", "rewrite ^ /unmask/challenge/", "error_page 429", "set $unmask_gated"} {
			if strings.Contains(inc, bad) {
				t.Errorf("degraded protect.inc still carries %q", bad)
			}
		}
		if !strings.Contains(inc, "NATIVE FAIL-SAFE ACTIVE") {
			t.Error("degraded protect.inc has no banner")
		}
		// The full render has the gate and the rate limit.
		if !strings.Contains(full["protect.inc"], "limit_req zone=") || !strings.Contains(full["protect.inc"], "$unmask_gate") {
			t.Error("the full protect.inc lost its rate limit or gate")
		}
	})

	t.Run("server_inc_keeps_the_admin_reachable", func(t *testing.T) {
		inc := deg["server.inc"]
		for _, want := range []string{
			"location ^~ /unmask/admin/ {",
			"location ^~ /unmask/ {",
			"proxy_pass         http://unmask_daemon;",
			`proxy_set_header   X-Unmask-Conn-Peer "";`,
			`proxy_set_header   X-Unmask-Site    "";`,
			"access_log syslog:server=unix:/run/unmask/log.sock unmask_minimal if=$unmask_log_keep;",
			"NATIVE FAIL-SAFE ACTIVE",
		} {
			if !strings.Contains(inc, want) {
				t.Errorf("degraded server.inc lost %q", want)
			}
		}
		for _, bad := range []string{
			`if ($unmask_ban_action_effective = "deny")`,
			`if ($unmask_banned_effective = "1")`,
			`if ($unmask_deny_now = "1")`,
			`if ($unmask_signed_gate = "1")`,
			`if ($unmask_pat_gate = "1")`,
		} {
			if strings.Contains(inc, bad) {
				t.Errorf("degraded server.inc still enforces: %q", bad)
			}
		}
		for _, want := range []string{`if ($unmask_ban_action_effective = "deny")`, `if ($unmask_banned_effective = "1")`} {
			if !strings.Contains(full["server.inc"], want) {
				t.Errorf("the full server.inc lost %q", want)
			}
		}
	})

	t.Run("its_own_render_id", func(t *testing.T) {
		// The switch into or out of the degraded render is a change nginx
		// must load: the id changes with it, so the reload notice and the
		// marker both fire.
		ids := map[string]string{}
		for _, f := range []string{"http.inc"} {
			ids["deg"] = renderIDRE.FindStringSubmatch(deg[f])[1]
			ids["full"] = renderIDRE.FindStringSubmatch(full[f])[1]
		}
		if ids["deg"] == "" || ids["deg"] == ids["full"] {
			t.Errorf("degraded render id %q vs full %q: want two ids", ids["deg"], ids["full"])
		}
	})
}

// The undefined-variable guard, applied to the DEGRADED output: every
// $unmask_* and $client_ja4 the rendered files read must be defined by a
// map, set or geo in those same files -- there is no module to define any.
// The static guard (undefined_vars_test.go) allows what the module source
// registers; here nothing is allowed.  Run over the configurations that wire
// the most variables, since each feature adds maps that read others.
func TestDegradedRenderDefinesEveryVariable(t *testing.T) {
	useRe := regexp.MustCompile(`\$\{?(unmask_[a-z0-9_]+|client_ja4)\b`)
	defRe := regexp.MustCompile(`(?:map\b[^{]*\$|set\s+\$|geo\b[^{]*\$)(unmask_[a-z0-9_]+|client_ja4)\b`)

	variants := map[string]func(*settings.Settings){
		"default":        nil,
		"native_install": withLogAndBans,
		"monitor_mode": func(s *settings.Settings) {
			withLogAndBans(s)
			s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
		},
		"signed_agents": func(s *settings.Settings) {
			withLogAndBans(s)
			s.Nginx.AdvancedEnabled = true
			s.Nginx.WebBotAuth.Enabled = true
			s.Nginx.PrivacyPass.Enabled = true
		},
		"deny_rules_and_redirect": func(s *settings.Settings) {
			withLogAndBans(s)
			s.Nginx.HTTPSRedirect = true
			s.Nginx.ChallengeTargets.Extra = []string{"contains:Bytespider"}
			s.Nginx.ChallengeTargets.ExtraAction = []string{settings.RateChallengeDeny}
			s.Nginx.Geo.Rules = []settings.GeoRule{{Country: "CN", Action: settings.RateChallengeDeny, Enabled: true}}
		},
		"header_tiers_and_lb": func(s *settings.Settings) {
			withLogAndBans(s)
			s.Global.HeaderIntegrity = true
			s.Global.StaleBrowserChallenge = true
			s.Global.CurrentChromeMajor = 150
			s.Global.StaleBrowserLag = 11
			s.Nginx.TrustedLBPresets = []string{"gcp"}
		},
		"community_bans": func(s *settings.Settings) {
			withLogAndBans(s)
			s.CommunityBans.SubscribeMode = settings.SubscribeFetchApply
			s.CommunityBans.Action = settings.RateChallengeDeny
		},
	}
	names := make([]string, 0, len(variants))
	for n := range variants {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			_, files := renderFiles(t, true, variants[name])
			used, defined := map[string]bool{}, map[string]bool{}
			for _, body := range files {
				body = withoutComments(body)
				for _, m := range useRe.FindAllStringSubmatch(body, -1) {
					used[m[1]] = true
				}
				for _, m := range defRe.FindAllStringSubmatch(body, -1) {
					defined[m[1]] = true
				}
			}
			var undef []string
			for v := range used {
				if !defined[v] {
					undef = append(undef, "$"+v)
				}
			}
			sort.Strings(undef)
			if len(undef) > 0 {
				t.Errorf("the degraded render reads variables nothing defines (the module is not loaded): %v", undef)
			}
		})
	}
}

// withoutComments drops what nginx does not read: comment lines, and a
// comment after a directive.  The rendered files explain themselves at
// length, naming variables other branches define.
func withoutComments(body string) string {
	var out []string
	for _, ln := range strings.Split(body, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if i := strings.Index(ln, " #"); i >= 0 {
			ln = ln[:i]
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// A render that changed a file leaves the reload marker naming its id, for
// whatever applies reloads; a render that changed nothing leaves the marker
// as it was; and the marker goes only for the id it names, so a verdict
// about an older render cannot clear a newer one's.
func TestReloadNeededMarker(t *testing.T) {
	dir := t.TempDir()
	renderInto(t, dir, "test", withLogAndBans)
	id1, _ := RenderIDOnDisk(dir)
	if got, ok := ReloadNeeded(dir); !ok || got != id1 {
		t.Fatalf("after the first render: marker=%q ok=%v, want %q", got, ok, id1)
	}

	// The same configuration again: nothing changed, the marker stays.
	renderInto(t, dir, "another-build", withLogAndBans)
	if got, ok := ReloadNeeded(dir); !ok || got != id1 {
		t.Fatalf("after a no-op render: marker=%q ok=%v, want %q kept", got, ok, id1)
	}

	// Cleared for another id: stays.  For its own: goes.
	if ClearReloadNeeded(dir, "000000000000") {
		t.Error("the marker was cleared for an id it does not name")
	}
	if !ClearReloadNeeded(dir, id1) {
		t.Error("the marker was not cleared for its own id")
	}
	if _, ok := ReloadNeeded(dir); ok {
		t.Error("the marker is still there after it was cleared")
	}
	if ClearReloadNeeded(dir, id1) {
		t.Error("a second clear reported a marker that was already gone")
	}

	// A change: the marker is back with the new id.
	renderInto(t, dir, "test", func(s *settings.Settings) {
		withLogAndBans(s)
		s.Nginx.HTTPSRedirect = true
	})
	id2, _ := RenderIDOnDisk(dir)
	if got, ok := ReloadNeeded(dir); !ok || got != id2 || id2 == id1 {
		t.Fatalf("after a change: marker=%q ok=%v, want the new id %q (old %q)", got, ok, id2, id1)
	}
	_ = ClearReloadNeeded(dir, "")

	// The fail-safe marker appearing is a change too: the degraded render
	// has its own id and waits for its reload like any other.
	if err := os.WriteFile(filepath.Join(dir, FailsafeMarker), []byte("reason: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	renderInto(t, dir, "test", func(s *settings.Settings) {
		withLogAndBans(s)
		s.Nginx.HTTPSRedirect = true
	})
	id3, _ := RenderIDOnDisk(dir)
	if got, ok := ReloadNeeded(dir); !ok || got != id3 || id3 == id2 {
		t.Fatalf("after the fail-safe: marker=%q ok=%v, want the degraded id %q (full %q)", got, ok, id3, id2)
	}
	if active, reason, since := FailsafeState(dir); !active || reason != "test" || since.IsZero() {
		t.Errorf("FailsafeState: active=%v reason=%q since=%v", active, reason, since)
	}
	if FailsafeActive("") || FailsafeActive(filepath.Join(dir, "nowhere")) {
		t.Error("FailsafeActive reports a marker where there is none")
	}

	// An install whose access log does not reach the daemon (forward-auth)
	// gets no marker: nothing could ever clear it.
	quiet := t.TempDir()
	renderInto(t, quiet, "test", nil)
	if _, ok := ReloadNeeded(quiet); ok {
		t.Error("a render with no access log to the daemon left a reload marker")
	}
}
