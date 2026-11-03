package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The rendered shape of one exemption: a flag the redirect's key folds in,
// never a `break` (see TestRedirectExemptGatesStillRun).
const (
	exemptFlag    = `{ set $unmask_https_redirect_exempt "1"; }`
	redirectKey   = `set $unmask_https_redirect_key "$unmask_forwarded_proto$unmask_https_redirect_exempt";`
	redirectCheck = `if ($unmask_https_redirect_key = "http")`
)

// TestRedirectExemptDefaults: with the redirect on and no operator changes,
// both default-on presets render before the 301 — ACME as a path flag, LB
// health checks as a user-agent flag (the axis that catches probes reaching
// the backend without X-Forwarded-Proto).
func TestRedirectExemptDefaults(t *testing.T) {
	got := renderServerInc(t, func(s *settings.Settings) {
		s.Nginx.HTTPSRedirect = true
	})
	redir := strings.Index(got, "return 301 https://")
	if redir < 0 {
		t.Fatalf("redirect missing:\n%s", got)
	}
	acme := strings.Index(got, `if ($request_uri ~ "^/\\.well-known/acme-challenge/") `+exemptFlag)
	if acme < 0 || acme > redir {
		t.Errorf("ACME path flag must render before the 301 (acme=%d redir=%d):\n%s", acme, redir, got)
	}
	ua := strings.Index(got, `if ($http_user_agent ~* "^(GoogleHC|ELB-HealthChecker|kube-probe`)
	if ua < 0 || ua > redir {
		t.Errorf("LB-health UA flag must render before the 301 (ua=%d redir=%d):\n%s", ua, redir, got)
	}
	key := strings.Index(got, redirectKey)
	check := strings.Index(got, redirectCheck)
	if key < 0 || check < 0 || key < ua || key > check || check > redir {
		t.Errorf("the redirect must test the key joined after the flags (ua=%d key=%d check=%d redir=%d):\n%s", ua, key, check, redir, got)
	}
}

// TestRedirectExemptGatesStillRun: an exemption withholds the redirect and
// nothing else.  Until 0.1.54 each one was a rewrite-phase `break`, which
// ends the server rewrite phase: the ban and the hard deny after the
// redirect never ran for an exempt request, so a banned client that named a
// health checker's user-agent walked past both to the ordinary challenge.
// So: no `break` anywhere in server.inc, the flag initialised before the
// first exemption reads it, and the ban gates after the redirect as before
// (TestHTTPSRedirectEmittedBeforeGates pins that order).  The fail-open
// scaffolding (`set $unmask_orig_path ""` / `$unmask_orig_args`) stays
// ahead of the block, so nothing reads it uninitialized.
func TestRedirectExemptGatesStillRun(t *testing.T) {
	got := renderServerInc(t, func(s *settings.Settings) {
		s.Nginx.HTTPSRedirect = true
		withLogAndBans(s)
		s.Nginx.Geo.Rules = []settings.GeoRule{{Country: "CN", Action: settings.RateChallengeDeny, Enabled: true}}
	})
	if i := strings.Index(got, "break;"); i >= 0 {
		t.Errorf("server.inc must not `break` out of the rewrite phase (offset %d): a break skips the ban and deny gates for the exempt request:\n%s", i, got)
	}
	first := strings.Index(got, exemptFlag)
	init := strings.Index(got, `set $unmask_https_redirect_exempt "";`)
	if first < 0 || init < 0 || init > first {
		t.Fatalf("the flag must be initialised before the first exemption sets it (init=%d first=%d):\n%s", init, first, got)
	}
	for _, want := range []string{`set $unmask_orig_path "";`, `set $unmask_orig_args "";`} {
		if i := strings.Index(got, want); i < 0 || i > first {
			t.Errorf("fail-open scaffolding %q must precede the exemptions (i=%d first=%d)", want, i, first)
		}
	}
	redir := strings.Index(got, "return 301 https://")
	for _, gate := range []string{
		`if ($unmask_ban_action_effective = "deny")`,
		`if ($unmask_banned_effective = "1")`,
		`if ($unmask_deny_now = "1")`,
	} {
		g := strings.Index(got, gate)
		if g < 0 {
			t.Errorf("gate %q missing:\n%s", gate, got)
			continue
		}
		if g < redir {
			t.Errorf("gate %q (idx %d) must follow the redirect (idx %d) so a plaintext request is redirected first", gate, g, redir)
		}
	}
}

// TestRedirectExemptDisablePreset: disabling the acme preset drops its flag;
// the lb-health preset stays.
func TestRedirectExemptDisablePreset(t *testing.T) {
	got := renderServerInc(t, func(s *settings.Settings) {
		s.Nginx.HTTPSRedirect = true
		s.Nginx.HTTPSRedirectExempt.DisabledPresets = []string{"acme"}
	})
	// Check for the DIRECTIVE, not the substring (a template comment also
	// mentions acme-challenge).
	if strings.Contains(got, `if ($request_uri ~ "^/\\.well-known/acme-challenge/") `+exemptFlag) {
		t.Errorf("disabled acme preset must not render its flag:\n%s", got)
	}
	if !strings.Contains(got, "GoogleHC") {
		t.Errorf("lb-health preset should still render:\n%s", got)
	}
}

// TestRedirectExemptCustomRules: a custom UA rule renders a user-agent flag,
// a custom path rule renders a request_uri flag, and a disabled row is
// skipped — all before the 301.
func TestRedirectExemptCustomRules(t *testing.T) {
	got := renderServerInc(t, func(s *settings.Settings) {
		s.Nginx.HTTPSRedirect = true
		s.Nginx.HTTPSRedirectExempt.Rules = []settings.HTTPSRedirectExemptRule{
			{Type: "ua", Pattern: "^MyMonitor"},
			{Type: "path", Pattern: "^/internal/"},
			{Type: "path", Pattern: "^/skip-me/", Disabled: true},
		}
	})
	redir := strings.Index(got, "return 301 https://")
	for _, want := range []string{
		`if ($http_user_agent ~* "^MyMonitor") ` + exemptFlag,
		`if ($request_uri ~ "^/internal/") ` + exemptFlag,
	} {
		i := strings.Index(got, want)
		if i < 0 || i > redir {
			t.Errorf("custom exemption %q must render before the 301 (i=%d redir=%d):\n%s", want, i, redir, got)
		}
	}
	if strings.Contains(got, "skip-me") {
		t.Errorf("disabled custom row must not render:\n%s", got)
	}
}

// TestRedirectExemptOffWhenRedirectOff: no exemptions render when the redirect
// itself is off (there is nothing to exempt from).
func TestRedirectExemptOffWhenRedirectOff(t *testing.T) {
	got := renderServerInc(t, nil)
	if strings.Contains(got, "GoogleHC") || strings.Contains(got, "acme-challenge") {
		t.Errorf("no exemptions should render when the redirect is off:\n%s", got)
	}
}

// TestEffectiveRedirectExemptPresets: both presets default on; explicit disable
// turns one off; an unknown id is ignored.
func TestEffectiveRedirectExemptPresets(t *testing.T) {
	def := EffectiveRedirectExemptPresets(nil, nil)
	if !def["acme"] || !def["lb-health"] {
		t.Errorf("both presets should default on: %+v", def)
	}
	dis := EffectiveRedirectExemptPresets(nil, []string{"lb-health"})
	if dis["lb-health"] {
		t.Errorf("explicitly disabled lb-health should be off: %+v", dis)
	}
	if !dis["acme"] {
		t.Errorf("acme should stay on: %+v", dis)
	}
}

// A custom exemption stored with a mode marker renders as the resolved regex
// (rx), the way every other pattern map does -- the marker itself would have
// been written into the `if` verbatim and matched nothing.
func TestRedirectExemptCustomRulesResolveMarkers(t *testing.T) {
	got := renderServerInc(t, func(s *settings.Settings) {
		s.Nginx.HTTPSRedirect = true
		s.Nginx.HTTPSRedirectExempt.Rules = []settings.HTTPSRedirectExemptRule{
			{Type: "path", Pattern: "contains:/.well-known/"},
			{Type: "ua", Pattern: "exact:MyMonitor/1.0"},
		}
	})
	for _, want := range []string{
		`if ($request_uri ~ "/\\.well-known/") ` + exemptFlag,
		`if ($http_user_agent ~* "^MyMonitor/1\\.0$") ` + exemptFlag,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("want %s in:\n%s", want, got)
		}
	}
	for _, marker := range []string{"contains:", "exact:"} {
		if strings.Contains(got, marker) {
			t.Errorf("marker %q leaked into server.inc", marker)
		}
	}
}
