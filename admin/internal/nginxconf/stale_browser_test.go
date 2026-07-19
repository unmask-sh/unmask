package nginxconf

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestStaleBrowserPattern: the generated nginx regex matches exactly the
// Chromium majors the daemon's classify.IsStaleBrowser treats as stale, and
// its trailing-dot anchor rejects prefix/suffix confusions.
func TestStaleBrowserPattern(t *testing.T) {
	// current=150 lag=11 -> threshold 139 (matches the incident tuning).
	pat := staleBrowserPattern(150, 11)
	if pat == "" {
		t.Fatal("expected a pattern for current=150 lag=11")
	}
	re := regexp.MustCompile(pat)
	stale := []string{"Chrome/139.0.7258.5", "Chrome/138.0.0.0", "Chrome/65.0.3325.181", "Chrome/1.0"}
	fresh := []string{"Chrome/140.0.0.0", "Chrome/149.0.0.0", "Chrome/150.0.0.0", "Chrome/151.0.0.0"}
	for _, ua := range stale {
		if !re.MatchString(ua) {
			t.Errorf("pattern must match stale %q", ua)
		}
	}
	for _, ua := range fresh {
		if re.MatchString(ua) {
			t.Errorf("pattern must NOT match fresh %q", ua)
		}
	}
	// Anchor guards: a build number that superficially contains a stale major
	// must not match (the token is Chrome/<major>. only).
	if re.MatchString("Chrome/1400.0.0.0") {
		t.Error("Chrome/1400 must not match via the 140/14 prefixes")
	}
	if re.MatchString("Chrome/1390") {
		t.Error("Chrome/1390 (no dot) must not match")
	}
	// A lag so large nothing qualifies yields no pattern.
	if staleBrowserPattern(150, 200) != "" {
		t.Error("threshold < 1 must yield an empty pattern")
	}
}

// TestStaleBrowserRenderOffByDefault: with the tier off, http.inc is free of
// any stale wiring (zero-diff on upgrade) and $final_challenge stays the base
// map output directly.
func TestStaleBrowserRenderOffByDefault(t *testing.T) {
	off := renderHTTPInc(t, nil)
	for _, absent := range []string{"unmask_stale_browser", "final_challenge_base", "Stale-browser tier"} {
		if strings.Contains(off, absent) {
			t.Errorf("tier off: %q must not render", absent)
		}
	}
	// The base map must still output straight to $final_challenge.
	if !strings.Contains(off, "$serve_bot_challenge\" $final_challenge {") {
		t.Error("tier off: final_challenge map must keep its original output var")
	}
}

// TestStaleBrowserRenderOn: enabling the tier wires the stale map, the
// escalation combiner, and reroutes the base map into $final_challenge_base.
func TestStaleBrowserRenderOn(t *testing.T) {
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.StaleBrowserChallenge = true
		s.Global.CurrentChromeMajor = 150
		s.Global.StaleBrowserLag = 11
	})
	for _, want := range []string{
		`map $http_user_agent $unmask_stale_browser {`,
		`$serve_bot_challenge" $final_challenge_base {`,
		`"~^0:1:0:0:0:0$"     1;`,
		`Chrome/(?:139|`,
	} {
		if !strings.Contains(on, want) {
			t.Errorf("tier on: expected %q in http.inc", want)
		}
	}
	// The combiner must default to the base decision (so every base=1 challenge
	// survives unchanged).
	if !strings.Contains(on, "default              $final_challenge_base;") {
		t.Error("tier on: combiner must default to the base decision")
	}
}

// TestStaleBrowserRenderUsesBuiltinBaseline: the toggle on with current major
// unset (0) still renders, riding the shipped DefaultCurrentChromeMajor so the
// tier works out of the box.  The threshold uses the baseline minus the lag.
func TestStaleBrowserRenderUsesBuiltinBaseline(t *testing.T) {
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.StaleBrowserChallenge = true
		s.Global.CurrentChromeMajor = 0 // ride the built-in baseline
		s.Global.StaleBrowserLag = 10
	})
	if !strings.Contains(on, "map $http_user_agent $unmask_stale_browser {") {
		t.Error("toggle on must render the tier using the built-in baseline even with current major unset")
	}
	// baseline (DefaultCurrentChromeMajor) - lag = threshold; the top stale
	// major is one below that boundary and must appear in the pattern.
	top := settings.DefaultCurrentChromeMajor - 10
	if !strings.Contains(on, "Chrome/(?:"+strconv.Itoa(top)+"|") {
		t.Errorf("expected top stale major %d in the pattern", top)
	}
}
