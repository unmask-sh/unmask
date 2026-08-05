package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func renderPair(t *testing.T, s settings.Settings) (httpInc, serverInc string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	if err := Render(s, dir, "test"); err != nil {
		t.Fatal(err)
	}
	h, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	sv, err := os.ReadFile(filepath.Join(dir, "server.inc"))
	if err != nil {
		t.Fatal(err)
	}
	return string(h), string(sv)
}

// An install that denies nothing must not pay for the deny axis.
//
// The dispatch is an `if` in the SERVER rewrite phase, which is read on every
// request to the vhost -- including requests served by locations that never
// include protect.inc.  Those never read $final_challenge, so today they never
// build $is_search_bot either; making them build $unmask_deny_now would add a
// UA-regex sweep per request to answer a question with one possible answer.
//
// (Where protect.inc IS included the marginal cost is small, because
// $final_challenge is a composite-key map: nginx builds every input to form the
// key, so those variables are already computed and cached for the request.  The
// pass cookie short-circuits the decision, never the computation.)
func TestNoDenyRuleRendersNoDenyPlumbing(t *testing.T) {
	httpInc, serverInc := renderPair(t, settings.Settings{})

	for _, v := range []string{"$unmask_deny_now", "$unmask_deny_raw", "$unmask_axis_deny", "$unmask_ua_deny"} {
		if strings.Contains(httpInc, v) {
			t.Errorf("http.inc builds %s on an install with nothing to deny", v)
		}
	}
	if strings.Contains(serverInc, "$unmask_deny_now") {
		t.Error("server.inc evaluates the deny dispatch on every request with nothing to deny")
	}
	if strings.Contains(serverInc, "/unmask/_deny") {
		t.Error("server.inc rewrites to the deny page on an install with nothing to deny")
	}
}

// ...and appears as soon as one exists, by any of the three routes.
func TestADenyRuleRendersTheDispatch(t *testing.T) {
	uaRow := settings.Settings{}
	uaRow.Nginx.ChallengeTargets.Extra = []string{"contains:Bytespider"}
	uaRow.Nginx.ChallengeTargets.ExtraAction = []string{settings.RateChallengeDeny}

	geo := settings.Settings{}
	geo.Nginx.Geo.Rules = []settings.GeoRule{{Country: "CN", Action: settings.RateChallengeDeny, Enabled: true}}

	for name, s := range map[string]settings.Settings{"ua_row": uaRow, "geo_rule": geo} {
		t.Run(name, func(t *testing.T) {
			httpInc, serverInc := renderPair(t, s)
			if !strings.Contains(httpInc, "$unmask_deny_now") {
				t.Error("http.inc does not build the deny signal")
			}
			if !strings.Contains(serverInc, "/unmask/_deny") {
				t.Error("server.inc does not dispatch the deny")
			}
			// The rescues have to gate the deny, or the fix would override an
			// exemption the operator set on purpose.
			raw := strings.Index(httpInc, "$unmask_deny_raw {")
			unresc := strings.Index(httpInc, "$unmask_deny_unrescued {")
			if raw < 0 || unresc < 0 {
				t.Fatal("the deny signal is not built from a rescue check")
			}
			if !strings.Contains(httpInc[raw:raw+200], "$unmask_deny_unrescued") {
				t.Error("$unmask_deny_raw does not consult the rescues")
			}
			for _, want := range []string{"$is_search_bot", "$is_bypass_ip", "$is_bypass_path"} {
				if !strings.Contains(httpInc[unresc-160:unresc], want) {
					t.Errorf("%s does not gate the deny", want)
				}
			}
			// ...but they must NOT be in a map KEY on the deny path.  nginx
			// builds a key eagerly and resolves only the matched value, so a
			// rescue in the key is paid by every request to the vhost, while a
			// rescue in the value is paid only by requests that matched a deny
			// rule.  Measured on a location without protect.inc (which
			// otherwise never builds these at all): 3.4k req/s in the key
			// against 28-36k through the value, on a 46k baseline.
			keyLine := httpInc[raw-40 : raw+len("$unmask_deny_raw {")]
			if strings.Contains(keyLine, "$is_search_bot") {
				t.Error("$is_search_bot sits in the eagerly-built deny key; every request to the vhost pays for it")
			}
		})
	}
	// A UA row is only in the map when its own action is deny.
	soft := settings.Settings{}
	soft.Nginx.ChallengeTargets.Extra = []string{"contains:Bytespider"}
	soft.Nginx.ChallengeTargets.ExtraAction = []string{settings.RateChallengePoWOnly}
	httpInc, _ := renderPair(t, soft)
	if strings.Contains(httpInc, "Bytespider") && strings.Contains(httpInc, "$unmask_ua_deny") {
		t.Error("a row pinned to pow_only reached the deny map")
	}
}
