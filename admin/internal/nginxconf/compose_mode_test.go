package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestNginxVersionGate pins the 1.17.1 boundary -- the release that added
// limit_req_dry_run, which compose mode depends on.
func TestNginxVersionGate(t *testing.T) {
	cases := []struct {
		out       string
		supported bool
		version   string
		ok        bool
	}{
		{"nginx version: nginx/1.17.1", true, "1.17.1", true},
		{"nginx version: nginx/1.17.0", false, "1.17.0", true},
		{"nginx version: nginx/1.16.1", false, "1.16.1", true},
		{"nginx version: nginx/1.10.3", false, "1.10.3", true}, // CentOS 6 / RHEL 6
		{"nginx version: nginx/1.18.0", true, "1.18.0", true},
		{"nginx version: nginx/1.30.0", true, "1.30.0", true},
		{"nginx version: nginx/1.30.0-1.el9.uic.ngx", true, "1.30.0", true}, // custom-build suffix
		{"not an nginx banner", false, "", false},
	}
	for _, c := range cases {
		sup, ver, ok := parseNginxDryRun(c.out)
		if sup != c.supported || ver != c.version || ok != c.ok {
			t.Errorf("parseNginxDryRun(%q) = (%v,%q,%v); want (%v,%q,%v)",
				c.out, sup, ver, ok, c.supported, c.version, c.ok)
		}
	}
}

// TestComposeCapableResolution: the RateComposeMode override wins; "" / "auto"
// follow the cached startup probe (default false → classic, safe everywhere).
func TestComposeCapableResolution(t *testing.T) {
	orig := DryRunSupported()
	t.Cleanup(func() { SetDryRunSupported(orig) })

	mk := func(mode string) settings.Settings {
		var s settings.Settings
		s.Nginx.RateComposeMode = mode
		return s
	}
	if !ComposeCapable(mk("always")) {
		t.Error(`RateComposeMode "always" must resolve compose`)
	}
	if ComposeCapable(mk("never")) {
		t.Error(`RateComposeMode "never" must resolve classic`)
	}
	SetDryRunSupported(false)
	if ComposeCapable(mk("")) || ComposeCapable(mk("auto")) {
		t.Error("auto with probe=false must be classic (safe default)")
	}
	SetDryRunSupported(true)
	if !ComposeCapable(mk("")) || !ComposeCapable(mk("auto")) {
		t.Error("auto with probe=true must be compose")
	}
}

// TestHasDenyRateZone covers the default-deny, named-deny, and challenge-only
// cases feeding the "deny can't compose on this nginx" warning.
func TestHasDenyRateZone(t *testing.T) {
	var challengeOnly settings.Settings
	challengeOnly.RateLimit.Zones = challengeZones()
	if HasDenyRateZone(challengeOnly) {
		t.Error("challenge-only config must not report a deny zone")
	}
	var namedDeny settings.Settings
	namedDeny.RateLimit.Zones = denyZones()
	if !HasDenyRateZone(namedDeny) {
		t.Error("a named deny zone must be reported")
	}
	var defaultDeny settings.Settings
	defaultDeny.RateLimit.Default.ChallengeMode = settings.RateChallengeDeny
	if !HasDenyRateZone(defaultDeny) {
		t.Error("a deny default must be reported")
	}
}

// TestNonDenyCompose is the new common case under version-based mode selection:
// a challenge-only config on modern nginx renders COMPOSE.  The plugin's
// ACCESS-phase handler runs the challenge (its captcha branch is unconditional,
// not version-gated), so protect.inc must carry the compose markers and drop the
// classic error_page-429 + REWRITE-phase challenge gate.
func TestNonDenyCompose(t *testing.T) {
	protect := renderRate(t, challengeZones(), "always", "protect.inc")
	for _, want := range []string{"limit_req_dry_run on;", "set $unmask_compose 1;"} {
		if !strings.Contains(protect, want) {
			t.Errorf("non-deny compose protect.inc missing %q", want)
		}
	}
	if strings.Contains(protect, "error_page 429") {
		t.Error("non-deny compose protect.inc must not arm the classic error_page-429 gate")
	}
	if strings.Contains(protect, "rewrite ^ /unmask/challenge/") {
		t.Error("non-deny compose protect.inc must not keep the classic REWRITE-phase challenge gate (the plugin challenges in ACCESS)")
	}
}

// TestDenyClassicNoDryRun is the CentOS 6 footgun fix: a deny zone forced onto
// the classic flow (old / undetectable nginx) must NOT emit limit_req_dry_run --
// that directive fails `nginx -t` on nginx < 1.17.1 and would take the whole
// config down on the next reload.  Classic keeps the error_page-429 gate; the
// deny still hard-blocks un-challenged traffic, it just can't preempt a challenge.
func TestDenyClassicNoDryRun(t *testing.T) {
	protect := renderRate(t, denyZones(), "never", "protect.inc")
	// The DIRECTIVE `limit_req_dry_run on;`, not the two-line mode legend comment
	// (which names limit_req_dry_run for both branches).  The directive is what
	// nginx < 1.17.1 rejects.
	if strings.Contains(protect, "limit_req_dry_run on;") {
		t.Error("deny zone on classic must NOT emit the limit_req_dry_run directive (fails nginx -t on <1.17.1)")
	}
	if !strings.Contains(protect, "error_page 429") {
		t.Error("deny zone on classic must keep the classic error_page-429 gate")
	}
}
