package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestPathPolicyMapsKeyedOnNormalizedURI guards the fix for the path
// decision / routing mismatch: the path-policy maps are decided on $uri (the
// normalized, decoded path nginx actually routes and serves), not on the raw
// $request_uri.
//
// With the raw $request_uri, a request like `/static/%2e%2e/admin` matched the
// default `^/static/` bypass (raw prefix) yet was routed and served as
// `/admin` (normalized) -- so an encoded traversal bought a bypass that turned
// off the challenge, rate limit, protected-path and honeypot axes, and the
// same mismatch let `/static/../secret` dodge a `^/secret` protected rule.
// Keying these maps on $uri removes the mismatch: the decision sees the same
// path that gets served.
//
// Honeypot and custom-rule path maps intentionally stay on $request_uri: they
// match the raw, undecoded form and the query string (see honeypot_sqli_test
// and custom_rules_render_test), so they must NOT be switched here.
func TestPathPolicyMapsKeyedOnNormalizedURI(t *testing.T) {
	inc := renderHTTPInc(t, nil)

	for _, want := range []string{
		"map $uri $unmask_bp_global {", // bypass paths
		"map $uri $unmask_pp_global {", // protected paths
		"map $uri $unmask_gx_global {", // geo-exempt paths
		"map $uri $unmask_ax_global {", // asn-exempt paths
	} {
		if !strings.Contains(inc, want) {
			t.Errorf("path-policy map not keyed on $uri: expected %q in http.inc", want)
		}
	}

	// The vulnerable raw-$request_uri keying must be gone for these axes.
	for _, bad := range []string{
		"map $request_uri $unmask_bp_global {",
		"map $request_uri $unmask_pp_global {",
		"map $request_uri $unmask_gx_global {",
		"map $request_uri $unmask_ax_global {",
	} {
		if strings.Contains(inc, bad) {
			t.Errorf("path-policy map still keyed on raw $request_uri: %q", bad)
		}
	}

	// Honeypot stays on the raw request URI (query string + undecoded probes).
	if !strings.Contains(inc, "map $request_uri $unmask_hp_global {") {
		t.Error("honeypot map must stay keyed on $request_uri (raw form + query)")
	}
}

// TestBanAndDenyMasksKeyedOnNormalizedURI: the ban and the hard deny are left
// off for unmask's own mounts ("/unmask/...") so that a banned visitor can
// still load the challenge.  Which requests those are is decided on $uri, as
// the path-policy maps above are: nginx routes by $uri, and with the raw
// $request_uri a banned or denied client that wrote "/unmask/../page" (or
// "/unmask/%2e%2e/page") was read as unmask's own traffic and served "/page".
// A deny ban answered 200, and a deny rule became the ordinary challenge.
func TestBanAndDenyMasksKeyedOnNormalizedURI(t *testing.T) {
	deny := func(s *settings.Settings) {
		s.Nginx.Honeypot.BanFilePath = "/var/lib/unmask/banned.txt"
		s.Nginx.ChallengeTargets.Extra = []string{"contains:Bytespider"}
		s.Nginx.ChallengeTargets.ExtraAction = []string{settings.RateChallengeDeny}
	}
	watch := func(s *settings.Settings) {
		deny(s)
		s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
	}
	for name, c := range map[string]struct {
		mutate func(*settings.Settings)
		want   []string
	}{
		"live": {deny, []string{
			"map $uri $unmask_ban_action_effective {",
			"map $uri $unmask_banned_effective {",
			"map $uri $unmask_deny_now {",
		}},
		"monitor mode": {watch, []string{
			`map "$unmask_observe:$uri" $unmask_ban_action_effective {`,
			`map "$unmask_observe:$uri" $unmask_banned_effective {`,
			"map $uri $unmask_deny_now {",
		}},
	} {
		inc := renderHTTPInc(t, c.mutate)
		for _, want := range c.want {
			if !strings.Contains(inc, want) {
				t.Errorf("%s: a ban / deny mask is not keyed on $uri: expected %q in http.inc", name, want)
			}
		}
		for _, v := range []string{"$unmask_ban_action_effective", "$unmask_banned_effective", "$unmask_deny_now"} {
			for _, ln := range strings.Split(inc, "\n") {
				if strings.HasPrefix(ln, "map ") && strings.HasSuffix(strings.TrimSpace(ln), v+" {") && strings.Contains(ln, "$request_uri") {
					t.Errorf("%s: %s is keyed on the raw $request_uri: %q", name, v, ln)
				}
			}
		}
	}
}

// TestBanAndDenyPagesAskedForByNormalizedURI: a deny ban and a hard deny are
// answered by the daemon's page at "/unmask/_ban<path>" and
// "/unmask/_deny<path>", and the path is $uri.  A rewrite takes its
// replacement as a path, so the request line as sent ($request_uri) reached
// the daemon with the query inside the path and once more behind it, with
// every %XX escaped a second time, and with a ".." segment still in it --
// which the daemon's router answers with a redirect to the resolved address:
// a banned client that wrote "/a/../page" got a 307 instead of the 403, and
// the hit was recorded only if it followed.
func TestBanAndDenyPagesAskedForByNormalizedURI(t *testing.T) {
	server := renderServerInc(t, func(s *settings.Settings) {
		s.Nginx.Honeypot.BanFilePath = "/var/lib/unmask/banned.txt"
		s.Nginx.ChallengeTargets.Extra = []string{"contains:Bytespider"}
		s.Nginx.ChallengeTargets.ExtraAction = []string{settings.RateChallengeDeny}
	})
	for _, want := range []string{
		"rewrite ^ /unmask/_ban$uri last;",
		"rewrite ^ /unmask/_deny$uri last;",
	} {
		if !strings.Contains(server, want) {
			t.Errorf("server.inc lacks %q", want)
		}
	}
	for _, bad := range []string{"/unmask/_ban$request_uri", "/unmask/_deny$request_uri"} {
		if strings.Contains(server, bad) {
			t.Errorf("server.inc asks for a page by the request line as sent: %q", bad)
		}
	}
}
