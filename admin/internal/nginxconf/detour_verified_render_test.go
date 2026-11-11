package nginxconf

import (
	"regexp"
	"strings"
	"testing"
)

// The Web Bot Auth and Privacy Pass detours count as verified only for the
// daemon's answer that names the credential.  The detour asks the whole
// forward-auth check, which also answers "pass" for a pass cookie or for a
// request none of its own axes flags; read as "verified", that skipped the
// configuration's own judgement -- a CAPTCHA-grade custom rule, the header
// tiers -- for any request that added a junk Signature-Input or PrivateToken
// header to a PoW cookie.
func TestDetourVerifiedOnlyForTheCredentialsAnswer(t *testing.T) {
	cases := []struct {
		name, file, variable, action, reason, credential string
	}{
		{"web bot auth", "http.inc", "$unmask_signed_verified", "$unmask_signed_action", "$unmask_signed_reason", "signed_agent:agent.example"},
		{"privacy pass", "http.inc", "$unmask_pat_verified", "$unmask_pat_action", "$unmask_pat_reason", "privacy_pass:issuer.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var httpInc, serverInc string
			if tc.name == "web bot auth" {
				httpInc, serverInc = renderWBA(t, true, "http.inc"), renderWBA(t, true, "server.inc")
			} else {
				httpInc, serverInc = renderPP(t, true, "http.inc"), renderPP(t, true, "server.inc")
			}
			if want := "auth_request_set " + tc.reason + " $upstream_http_x_unmask_reason;"; !strings.Contains(serverInc, want) {
				t.Fatalf("server.inc does not capture the reason: want %q", want)
			}
			head := `map "` + tc.action + `:` + tc.reason + `" ` + tc.variable + ` {`
			i := strings.Index(httpInc, head)
			if i < 0 {
				t.Fatalf("http.inc has no %q", head)
			}
			body := httpInc[i:]
			body = body[:strings.Index(body, "\n}")]
			// The map's one regex key, read back and applied to the answers
			// the daemon gives.  A default of 0 covers everything else.
			m := regexp.MustCompile(`"~(\^[^"]+)"\s+1;`).FindStringSubmatch(body)
			if m == nil || !strings.Contains(body, "default") {
				t.Fatalf("unexpected map body:\n%s", body)
			}
			re := regexp.MustCompile(m[1])
			if !re.MatchString("pass:" + tc.credential) {
				t.Errorf("the credential's own pass (%q) is not verified", tc.credential)
			}
			for _, other := range []string{"pass:bv-pow", "pass:bv-captcha", "pass:ok", "pass:human", "pass:ua:search_ai", "challenge:" + tc.credential, ":"} {
				if re.MatchString(other) {
					t.Errorf("the answer %q counts as verified", other)
				}
			}
		})
	}
}
