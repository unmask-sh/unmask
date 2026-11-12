package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestUpstreamServerOK(t *testing.T) {
	for v, want := range map[string]bool{
		"127.0.0.1:9477":             true,
		"unmask:9477":                true, // a compose service
		"my_service.internal:9477":   true,
		"[::1]:9477":                 true,
		"[2001:db8::10]:9477":        true,
		"[::1]":                      true,
		"127.0.0.1":                  true,
		"unmask":                     true,
		"unix:/run/unmask/http.sock": true,

		"":                                 false,
		"::1":                              false, // nginx wants the brackets
		"[127.0.0.1]":                      false,
		"127.0.0.1:9477;":                  false,
		"127.0.0.1:9477; include /x.conf":  false,
		"127.0.0.1:9477 backup":            false,
		"127.0.0.1:0":                      false,
		"127.0.0.1:99999":                  false,
		"127.0.0.1:09477":                  false,
		"a b:9477":                         false,
		"host}:9477":                       false,
		"127.0.0.1:9477\n}":                false,
		"unix:run/unmask/http.sock":        false,
		"unix:/run/unmask/http.sock; x":    false,
		"unix:/run/unmask/a b.sock":        false,
		"unix:/run/unmask/http.sock\nevil": false,
		"-host:9477":                       false,
	} {
		if got := upstreamServerOK(v); got != want {
			t.Errorf("upstreamServerOK(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestSocketPathOK(t *testing.T) {
	for p, want := range map[string]bool{
		"/run/unmask/log.sock":     true,
		"/var/lib/unmask/l-o_g.s":  true,
		"":                         false,
		"run/unmask/log.sock":      false,
		"/run/unmask/log.sock x":   false,
		"/run/unmask/log.sock;":    false,
		"/run/unmask/log.sock,tag": false, // a second syslog parameter
		"/run/unmask/$x.sock":      false,
		"/run/unmask/log.sock\n#":  false,
		"/run/unmask/\"log\".sock": false,
		"/run/unmask/{a}.sock":     false,
	} {
		if got := socketPathOK(p); got != want {
			t.Errorf("socketPathOK(%q) = %v, want %v", p, got, want)
		}
	}
}

// renderAfterAPlainOne renders s into a directory that already holds a render's
// files ("the last render") and returns the directory, what it held before,
// and the second render's error.
func renderAfterAPlainOne(t *testing.T, mutate func(*settings.Settings)) (string, map[string]string, error) {
	t.Helper()
	dir := t.TempDir()
	var s settings.Settings
	s.Nginx.OutputDir = dir
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("the plain render: %v", err)
	}
	before := readDir(t, dir)
	mutate(&s)
	err := Render(s, dir, "test")
	return dir, before, err
}

func readDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// config.yml has writers the admin's forms do not check: an edit by hand, a
// configuration manager.  The daemon's address and the log socket are written
// into nginx's configuration as they stand, so a value that would end its
// directive and begin another is refused at the render -- which the config
// watch now runs seconds after such an edit -- and the files of the last
// render stay.
func TestRenderRefusesWhatWouldEndItsDirective(t *testing.T) {
	for name, mutate := range map[string]func(*settings.Settings){
		"upstream_addr": func(s *settings.Settings) {
			s.Nginx.UpstreamAddr = "127.0.0.1:9477; } include /tmp/evil.conf; upstream x { server 127.0.0.1:1"
		},
		"upstream_addr with a parameter": func(s *settings.Settings) {
			s.Nginx.UpstreamAddr = "127.0.0.1:9477 max_fails=0"
		},
		"server.bind": func(s *settings.Settings) {
			s.Server.Bind = "unix:/run/unmask/http.sock;\nload_module /tmp/evil.so"
		},
		"nginx_log.socket_path": func(s *settings.Settings) {
			s.NginxLog.Enabled = true
			s.NginxLog.SocketPath = "/run/unmask/log.sock unmask_minimal;\ninclude /tmp/evil.conf;\n#"
		},
		"nginx_log.socket_path while the log is off": func(s *settings.Settings) {
			// The path is named on a comment line either way.
			s.NginxLog.SocketPath = "/run/unmask/log.sock\ninclude /tmp/evil.conf;"
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, before, err := renderAfterAPlainOne(t, mutate)
			if err == nil {
				t.Fatal("the render went through")
			}
			if !strings.Contains(err.Error(), "render refused") || !strings.Contains(err.Error(), "config.yml") {
				t.Errorf("the error does not say what to fix: %v", err)
			}
			after := readDir(t, dir)
			if len(after) != len(before) {
				t.Errorf("the refused render changed the set of files: %d -> %d", len(before), len(after))
			}
			for name, body := range before {
				if after[name] != body {
					t.Errorf("the refused render rewrote %s", name)
				}
				if strings.Contains(after[name], "evil") {
					t.Errorf("%s carries the value", name)
				}
			}
		})
	}
}

// And the values an install uses go through as before.
func TestRenderTakesTheUsualAddresses(t *testing.T) {
	for _, mutate := range []func(*settings.Settings){
		func(s *settings.Settings) { s.Nginx.UpstreamAddr = "unmask:9477" },
		func(s *settings.Settings) { s.Nginx.UpstreamAddr = "[2001:db8::10]:9477" },
		func(s *settings.Settings) { s.Server.Bind = "unix:/run/unmask/http.sock" },
		func(s *settings.Settings) { s.Server.Bind = "0.0.0.0"; s.Server.Port = 9477 },
		func(s *settings.Settings) { s.Server.Bind = "[::]"; s.Server.Port = 9477 },
		func(s *settings.Settings) { s.Server.Bind = "::1"; s.Server.Port = 9477 },
		func(s *settings.Settings) {
			s.NginxLog.Enabled = true
			s.NginxLog.SocketPath = "/run/unmask/log.sock"
		},
	} {
		if _, _, err := renderAfterAPlainOne(t, mutate); err != nil {
			t.Errorf("a usual value was refused: %v", err)
		}
	}
}

// A trusted load balancer of one's own: its id names a variable and a map
// key, and its ranges go into a geo block unquoted.  The network tab checks
// both; from an edited config.yml, an entry whose id is not a name is left
// out, and so is a range that is not one -- the rest of the entry stays.
func TestLBExtraFromAnEditedConfig(t *testing.T) {
	extras := []settings.TrustedLBExtra{
		{ID: "good", CIDRs: []string{"203.0.113.0/24", " 198.51.100.7 "}},
		{ID: "bad id; }", CIDRs: []string{"203.0.113.0/24"}},
		{ID: "mixed", CIDRs: []string{"192.0.2.0/24", "10.0.0.0/8; } geo $x { default 1", "10.0.0.0/33"}},
		{ID: "none", CIDRs: []string{"not-a-range"}},
		{ID: "off", CIDRs: []string{"bogus"}, Disabled: true},
	}
	lbs := effectiveLBs(nil, extras)
	got := map[string][]string{}
	for _, lb := range lbs {
		got[lb.ID] = lb.CIDRs
	}
	if len(got) != 2 {
		t.Fatalf("entries kept: %v, want good and mixed", got)
	}
	if strings.Join(got["good"], ",") != "203.0.113.0/24,198.51.100.7" {
		t.Errorf("good: %q", got["good"])
	}
	if strings.Join(got["mixed"], ",") != "192.0.2.0/24" {
		t.Errorf("mixed: %q", got["mixed"])
	}
	// The caller's settings are not rewritten.
	if len(extras[2].CIDRs) != 3 || extras[0].CIDRs[1] != " 198.51.100.7 " {
		t.Errorf("effectiveLBs rewrote its input: %+v", extras)
	}

	w := lbExtraWarning(extras)
	for _, want := range []string{`"bad id; }"`, `"mixed"`, `"10.0.0.0/33"`, `"none"`, "trusted_lb_extra"} {
		if !strings.Contains(w, want) {
			t.Errorf("the warning does not name %s: %s", want, w)
		}
	}
	if strings.Contains(w, `"good"`) || strings.Contains(w, `"off"`) {
		t.Errorf("the warning names an entry that is fine or off: %s", w)
	}
	if lbExtraWarning(extras[:1]) != "" {
		t.Error("a warning for entries that are fine")
	}

	// And in the rendered file: no trace of the values left out.
	http := renderHTTP(t, func() settings.Settings {
		var s settings.Settings
		s.Nginx.TrustedLBExtra = extras
		return s
	}())
	for _, bad := range []string{"bad id", "geo $x", "10.0.0.0/33", "not-a-range"} {
		if strings.Contains(http, bad) {
			t.Errorf("http.inc carries %q", bad)
		}
	}
	if !strings.Contains(http, "192.0.2.0/24") || !strings.Contains(http, "203.0.113.0/24") {
		t.Error("http.inc lost the ranges that are fine")
	}
}
