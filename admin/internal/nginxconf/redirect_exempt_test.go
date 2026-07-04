package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestRedirectExemptDefaults: with the redirect on and no operator changes,
// both default-on presets render before the 301 — ACME as a path break, LB
// health checks as a user-agent break (the axis that catches probes reaching
// the backend without X-Forwarded-Proto).
func TestRedirectExemptDefaults(t *testing.T) {
	got := renderServerInc(t, func(s *settings.Settings) {
		s.Nginx.HTTPSRedirect = true
	})
	redir := strings.Index(got, "return 301 https://")
	if redir < 0 {
		t.Fatalf("redirect missing:\n%s", got)
	}
	acme := strings.Index(got, `if ($request_uri ~ "^/\.well-known/acme-challenge/") { break; }`)
	if acme < 0 || acme > redir {
		t.Errorf("ACME path break must render before the 301 (acme=%d redir=%d):\n%s", acme, redir, got)
	}
	ua := strings.Index(got, `if ($http_user_agent ~* "^(GoogleHC|ELB-HealthChecker|kube-probe`)
	if ua < 0 || ua > redir {
		t.Errorf("LB-health UA break must render before the 301 (ua=%d redir=%d):\n%s", ua, redir, got)
	}
}

// TestRedirectExemptDisablePreset: disabling the acme preset drops its break;
// the lb-health preset stays.
func TestRedirectExemptDisablePreset(t *testing.T) {
	got := renderServerInc(t, func(s *settings.Settings) {
		s.Nginx.HTTPSRedirect = true
		s.Nginx.HTTPSRedirectExempt.DisabledPresets = []string{"acme"}
	})
	// Check for the break DIRECTIVE, not the substring (a template comment also
	// mentions acme-challenge).
	if strings.Contains(got, `if ($request_uri ~ "^/\.well-known/acme-challenge/") { break; }`) {
		t.Errorf("disabled acme preset must not render its break:\n%s", got)
	}
	if !strings.Contains(got, "GoogleHC") {
		t.Errorf("lb-health preset should still render:\n%s", got)
	}
}

// TestRedirectExemptCustomRules: a custom UA rule renders a user-agent break, a
// custom path rule renders a request_uri break, and a disabled row is skipped —
// all before the 301.
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
		`if ($http_user_agent ~* "^MyMonitor") { break; }`,
		`if ($request_uri ~ "^/internal/") { break; }`,
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
