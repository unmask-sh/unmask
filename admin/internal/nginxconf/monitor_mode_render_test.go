package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// renderIncs renders every include into a scratch dir and returns http.inc,
// server.inc and protect.inc: monitor mode touches all three.
func renderIncs(t *testing.T, mutate func(*settings.Settings)) (httpInc, serverInc, protectInc string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	if mutate != nil {
		mutate(&s)
	}
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return read("http.inc"), read("server.inc"), read("protect.inc")
}

// TestMonitorModeRenderOff: with nobody in monitor mode the configuration is
// its usual self -- none of the mode's maps, no ob= in the log line, the gate
// reads the challenge decision directly and every zone counts against its own
// key.  Zero rendered diff on upgrade for an install that never uses the mode.
func TestMonitorModeRenderOff(t *testing.T) {
	httpInc, serverInc, protectInc := renderIncs(t, nil)
	for _, absent := range []string{"$unmask_observe", "$unmask_enforce", " ob=", "$unmask_rlk_"} {
		for name, text := range map[string]string{"http.inc": httpInc, "server.inc": serverInc, "protect.inc": protectInc} {
			if strings.Contains(text, absent) {
				t.Errorf("monitor mode off: %s must not contain %q", name, absent)
			}
		}
	}
	if !strings.Contains(protectInc, `set $unmask_gate "${final_challenge}:${unmask_failopen}";`) {
		t.Error("monitor mode off: the gate should read $final_challenge directly")
	}
	if !strings.Contains(httpInc, "map $request_uri $unmask_ban_action_effective {") {
		t.Error("monitor mode off: the ban dispatch should key on the URI alone")
	}
}

// TestMonitorModeRenderOn: with the default record in monitor mode, nginx
// itself lets every judged request through and says so in the log.  This is
// what replaced the daemon-side redirect that looped: nginx judges by the
// cookie alone, so a mode that hands out no cookie has to live in nginx.
func TestMonitorModeRenderOn(t *testing.T) {
	httpInc, _, protectInc := renderIncs(t, func(s *settings.Settings) {
		s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
	})
	for _, want := range []string{
		// the switch, 1 for every host
		"map $host $unmask_observe {\n    default 1;\n}",
		// the gate's decision: the challenge decision minus watched sites
		`map "$final_challenge:$unmask_observe" $unmask_enforce {`,
		// the log says the judgement was recorded, not enforced
		` cr=$unmask_cr_id ob=$unmask_observe rv=`,
		// a watched site enforces no ban ...
		`map "$unmask_observe:$request_uri" $unmask_ban_action_effective {`,
		`map "$unmask_observe:$request_uri" $unmask_banned_effective {`,
		// ... and is not counted toward any rate zone: the key maps lead with it
		`map "$unmask_observe:$bv_any_valid:$is_search_bot:$is_bypass_ip:$is_bypass_path" $rate_limit_key {`,
		`map "$unmask_observe:$is_search_bot:$is_bypass_ip:$is_bypass_path" $rate_limit_key_deny {`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("monitor mode on: http.inc missing %q", want)
		}
	}
	if !strings.Contains(protectInc, `set $unmask_gate "${unmask_enforce}:${unmask_failopen}";`) {
		t.Error("monitor mode on: protect.inc's gate should read $unmask_enforce")
	}
	// Every rate key map leads with the mode, or that zone would still count a
	// watched site's visitor.
	for _, line := range strings.Split(httpInc, "\n") {
		if strings.HasPrefix(line, `map "`) && strings.Contains(line, `" $rate_limit_key`) &&
			!strings.HasPrefix(line, `map "$unmask_observe:`) {
			t.Errorf("monitor mode on: a rate key map does not lead with the mode: %s", line)
		}
	}
	// The zones themselves keep the key variables they have with the mode off.
	// nginx refuses to reload a zone whose key variable changed ("uses the X
	// key while previously it used Y"), which would have made every toggle a
	// restart -- seen on the e2e stack the first time round.
	offInc, _, _ := renderIncs(t, nil)
	if got, want := zoneLines(httpInc), zoneLines(offInc); got != want {
		t.Errorf("monitor mode changes the zone declarations (reload would be refused):\n on: %s\noff: %s", got, want)
	}
	if strings.Contains(httpInc, "$unmask_rlk_") {
		t.Error("monitor mode on: a zone was re-keyed through a wrapper variable")
	}
}

// zoneLines returns the limit_req_zone declarations of a render, in order.
func zoneLines(inc string) string {
	var out []string
	for _, line := range strings.Split(inc, "\n") {
		if strings.HasPrefix(line, "limit_req_zone ") {
			out = append(out, line)
		}
	}
	return strings.Join(out, " | ")
}

// TestMonitorModeRenderPerSite: a site row overrides the default both ways,
// keyed the way $host arrives, and a disabled override resolves to the default.
func TestMonitorModeRenderPerSite(t *testing.T) {
	httpInc, _, _ := renderIncs(t, func(s *settings.Settings) {
		s.Challenge.Sites = map[string]settings.ChallengeValues{
			"watched.example.com":  {ObserveOnly: settings.BoolPtr(true)},
			"same.example.com":     {ObserveOnly: settings.BoolPtr(false)},
			"disabled.example.com": {ObserveOnly: settings.BoolPtr(true), Disabled: true},
		}
	})
	want := "map $host $unmask_observe {\n    default 0;\n    \"watched.example.com\" 1;\n}"
	if !strings.Contains(httpInc, want) {
		t.Errorf("per-site: want\n%s\nin http.inc", want)
	}
	for _, absent := range []string{`"same.example.com"`, `"disabled.example.com"`} {
		if strings.Contains(httpInc, absent) {
			t.Errorf("per-site: %s answers like the default and must not be listed", absent)
		}
	}

	// The other way round: the default watches, one site enforces.
	httpInc, _, _ = renderIncs(t, func(s *settings.Settings) {
		s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
		s.Challenge.Sites = map[string]settings.ChallengeValues{
			"live.example.com": {ObserveOnly: settings.BoolPtr(false)},
		}
	})
	want = "map $host $unmask_observe {\n    default 1;\n    \"live.example.com\" 0;\n}"
	if !strings.Contains(httpInc, want) {
		t.Errorf("per-site (default on): want\n%s\nin http.inc", want)
	}
}
