package handlers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Every gating axis has to exist on BOTH wires.
//
// The two are built from the same settings by different code: native renders
// nginx variables and lets the map chain decide, forward-auth answers in Go
// inside authCheck.  Nothing structural ties them together, so an axis added
// to one side simply does not exist on the other -- and the admin shows it as
// configured either way, which is what makes the gap invisible.  It has
// happened twice: the community feed enforced nothing on forward-auth for
// several releases while listing its entries as enforced, and the user-agent
// chain carried a fixed captcha_only there while every other path inherited
// the install default.
//
// This is the inventory: a row per axis, naming the variable native renders
// and the decision authCheck calls.  Adding an axis means adding a row, which
// cannot be filled in without wiring both sides; deleting one side of an
// existing axis fails here rather than in production.
//
// What it checks is presence, not agreement -- that both wires KNOW about the
// axis.  Whether they resolve it to the same action is per-axis work (see
// axis_parity_test.go, the path-syntax parity tests, and e2e scenario 58),
// because each axis agrees along its own settings.  Presence is the failure
// that shipped, twice, and it is the one a table can hold.
func TestEveryAxisExistsOnBothWires(t *testing.T) {
	axes := []struct {
		name string
		// nativeVar: the rendered nginx variable carrying this axis's verdict
		// into the challenge decision.
		nativeVar string
		// faCall: the decision authCheck makes for this axis, as it appears in
		// the source.  Deliberately the call site rather than a live call --
		// several of these need a database, a geo table or a ban manager, and
		// a unit test that stands those up would be testing them, not the
		// wiring.  What went missing before was the call site itself.
		faCall string
	}{
		{"ban", "$unmask_banned_eff", "banDecide("},
		{"community bans", "$unmask_cb_challenge", "communityBansDecide("},
		{"geo", "$geo_challenge_eff", "h.geoDecide("},
		{"asn", "$asn_challenge_eff", "h.asnDecide("},
		{"honeypot", "$is_bypass_path", "honeypotDecide("},
		{"protected paths", "$unmask_chmode", "protectedDecide("},
		{"ja4 verdict", "$is_known_browser", "ja4Decide("},
		{"header integrity", "$unmask_header_mismatch", "headerDecide("},
		{"challenge targets (UA)", "$is_challenge_target", "uaDecide("},
		{"search-bot rescue", "$is_search_bot", "isSearchBotUA("},
		{"bypass IP", "$is_bypass_ip", "rangeVerifiedUA"},
	}

	rendered := renderHTTPIncForParity(t)
	authCheck := readSource(t, "auth_check.go")

	for _, ax := range axes {
		t.Run(ax.name, func(t *testing.T) {
			if !strings.Contains(rendered, ax.nativeVar) {
				t.Errorf("native: %s is absent from the rendered http.inc -- this axis decides "+
					"nothing behind the nginx module, however it looks in the admin", ax.nativeVar)
			}
			if !strings.Contains(authCheck, ax.faCall) {
				t.Errorf("forward-auth: auth_check.go never calls %s -- this axis decides nothing "+
					"behind a load balancer or on Apache, however it looks in the admin", ax.faCall)
			}
		})
	}
}

// readSource reads a file from this package's own directory, so the test reads
// the source it ships beside rather than a path guessed from the working
// directory.
func readSource(t *testing.T, name string) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(self), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// renderHTTPIncForParity renders http.inc with the axes that need switching on
// switched on, so a variable missing from the output means the axis is absent
// rather than merely disabled.
func renderHTTPIncForParity(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	s.Global.HeaderIntegrity = true
	s.Nginx.BypassIPs = []string{"192.0.2.1"}
	s.Nginx.ChallengeTargets.DefaultAction = settings.RateChallengePoWOnly
	if err := nginxconf.Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatalf("read http.inc: %v", err)
	}
	return string(b)
}
