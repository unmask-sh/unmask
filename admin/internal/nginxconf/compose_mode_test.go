package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestNginxVersionGate pins the 1.17.6 boundary -- compose needs BOTH
// limit_req_dry_run (1.17.1) AND the r->main->limit_req_status field the module
// reads (1.17.6), so the higher one gates it (matches the module's
// `#if (nginx_version >= 1017006)`).
func TestNginxVersionGate(t *testing.T) {
	cases := []struct {
		out       string
		supported bool
		version   string
		ok        bool
	}{
		{"nginx version: nginx/1.17.6", true, "1.17.6", true},  // first supported
		{"nginx version: nginx/1.17.5", false, "1.17.5", true}, // dry_run exists, status field does not
		{"nginx version: nginx/1.17.1", false, "1.17.1", true}, // dry_run directive only
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
	// old nginx rejects.
	if strings.Contains(protect, "limit_req_dry_run on;") {
		t.Error("deny zone on classic must NOT emit the limit_req_dry_run directive (fails nginx -t on old nginx)")
	}
	if !strings.Contains(protect, "error_page 429") {
		t.Error("deny zone on classic must keep the classic error_page-429 gate")
	}
}

// TestNormalizeComposeMode: canonicalization + the known/unknown split that
// drives the unrecognized-value warning.
func TestNormalizeComposeMode(t *testing.T) {
	known := map[string]string{
		"":         "auto",
		"auto":     "auto",
		"  AUTO  ": "auto",
		"Always":   "always",
		"NEVER":    "never",
	}
	for in, want := range known {
		if got, ok := normalizeComposeMode(in); got != want || !ok {
			t.Errorf("normalizeComposeMode(%q) = (%q,%v); want (%q,true)", in, got, ok, want)
		}
	}
	for _, in := range []string{"classic", "compose", "on", "1", "yes"} {
		if got, ok := normalizeComposeMode(in); ok || got != "auto" {
			t.Errorf("normalizeComposeMode(%q) = (%q,%v); want (\"auto\",false)", in, got, ok)
		}
	}
}

// TestDiagnoseComposeMode: the classifier attributes the classic fallback to its
// ACTUAL cause and flags an unrecognized mode / a nginx-t-breaking always.
func TestDiagnoseComposeMode(t *testing.T) {
	deny := func() settings.Settings {
		var s settings.Settings
		s.RateLimit.Zones = denyZones()
		return s
	}
	mode := func(m string, s settings.Settings) settings.Settings { s.Nginx.RateComposeMode = m; return s }

	// unrecognized value -> warn, regardless of probe.
	if d := DiagnoseComposeMode(mode("bogus", settings.Settings{}), "", false, false); d.Level != ComposeDiagWarn ||
		!strings.Contains(d.Message, "unrecognized") {
		t.Errorf("bogus mode: got level=%v msg=%q", d.Level, d.Message)
	}
	// always on a confirmed old nginx -> error (nginx -t will fail).
	if d := DiagnoseComposeMode(mode("always", settings.Settings{}), "1.16.1", true, false); d.Level != ComposeDiagError ||
		!strings.Contains(d.Message, "1.17.6") {
		t.Errorf("always+old: got level=%v msg=%q", d.Level, d.Message)
	}
	// deny + never -> warn attributed to the operator's choice, not the version.
	if d := DiagnoseComposeMode(mode("never", deny()), "1.26.0", true, true); d.Level != ComposeDiagWarn ||
		!strings.Contains(d.Message, "never") {
		t.Errorf("deny+never: got level=%v msg=%q", d.Level, d.Message)
	}
	// deny + auto + no nginx on PATH -> warn attributed to the missing nginx.
	if d := DiagnoseComposeMode(mode("auto", deny()), "", false, false); d.Level != ComposeDiagWarn ||
		!strings.Contains(d.Message, "not detected") {
		t.Errorf("deny+undetected: got level=%v msg=%q", d.Level, d.Message)
	}
	// deny + capable -> OK "compose active".
	if d := DiagnoseComposeMode(mode("auto", deny()), "1.26.0", true, true); d.Level != ComposeDiagOK ||
		!strings.Contains(d.Message, "compose active") {
		t.Errorf("deny+capable: got level=%v msg=%q", d.Level, d.Message)
	}
	// no deny, capable -> OK, nothing to report.
	if d := DiagnoseComposeMode(mode("auto", settings.Settings{}), "1.26.0", true, true); d.Level != ComposeDiagOK || d.Message != "" {
		t.Errorf("no-deny: got level=%v msg=%q", d.Level, d.Message)
	}
}
