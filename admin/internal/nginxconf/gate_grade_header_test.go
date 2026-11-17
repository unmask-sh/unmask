package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestServerIncForwardsTheGatesCaptchaGrade: when any source can ask for a
// CAPTCHA-grade pass, server.inc hands the daemon the gate's own answer, so
// the page it serves can mint what the gate will ask for.  The case that
// needed it: a country default that ends in a CAPTCHA.  The geo block lists
// only the ranges of the countries a rule names and gives every other address
// the default -- an address the country database does not place included --
// while the daemon, which resolved no country for such an address, asked for
// nothing.  With no source live the header is cleared, so a client's own
// value never reaches the daemon either way.
func TestServerIncForwardsTheGatesCaptchaGrade(t *testing.T) {
	httpInc, serverInc, _ := renderIncs(t, func(s *settings.Settings) {
		s.Nginx.Geo = settings.GeoConfig{
			DefaultAction: settings.RateChallengeCaptchaOnly,
			Rules:         []settings.GeoRule{{Country: "JP", Action: settings.GeoActionSkip, Enabled: true}},
		}
	})
	for _, want := range []string{
		"geo $remote_addr $unmask_country {\n    default \"\";",
		"map $unmask_country $unmask_geo_action {\n    default \"captcha_only\";",
		"$unmask_needs_captcha_grade {",
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("a country default ending in a CAPTCHA: http.inc lacks %q", want)
		}
	}
	if !strings.Contains(serverInc, "proxy_set_header   X-Unmask-Needs-Captcha $unmask_needs_captcha_grade;") {
		t.Error("a country default ending in a CAPTCHA: server.inc does not hand the gate's requirement to the daemon")
	}

	// No source live.  The stock UA and JA4 lists already end in a CAPTCHA,
	// so the data is built and the flag taken down by hand rather than
	// through a dozen settings.
	var s settings.Settings
	d, err := buildRenderData(s, t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	d.GradeCheckedPass = false
	httpOff, err := renderToString("templates/http.conf.tmpl", d)
	if err != nil {
		t.Fatal(err)
	}
	serverOff, err := renderToString("templates/server.inc.tmpl", d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(httpOff, "$unmask_needs_captcha_grade {") {
		t.Fatal("precondition: with no CAPTCHA-grade source http.inc still defines the grade map")
	}
	if !strings.Contains(serverOff, `proxy_set_header   X-Unmask-Needs-Captcha "";`) {
		t.Error("no CAPTCHA-grade source: server.inc does not clear X-Unmask-Needs-Captcha")
	}
	if strings.Contains(serverOff, "$unmask_needs_captcha_grade") {
		t.Error("no CAPTCHA-grade source: server.inc names a variable http.inc does not define")
	}
}
