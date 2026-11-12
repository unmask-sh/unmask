package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// mapKey writes a literal key of an nginx map.  The words map reads as its
// own and a leading `~` take the escape (a backslash, doubled inside quotes);
// everything else comes out as nginxQuote leaves it, so the keys of an
// existing render do not move.
func TestMapKey(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"aws", `aws`},
		{"shop.example.com", `shop.example.com`},
		{"t13d1516h2_8daaf6152771_02713d6af862", `t13d1516h2_8daaf6152771_02713d6af862`},
		{"default", `\\default`},
		{"Default", `\\Default`},
		{"include", `\\include`},
		{"hostnames", `\\hostnames`},
		{"volatile", `\\volatile`},
		{"~not-a-regex", `\\~not-a-regex`},
		{`\leading`, `\\\\leading`},
		{`a"b`, `a\"b`},
		{"defaults", `defaults`},
	} {
		if got := mapKey(c.in); got != c.want {
			t.Errorf("mapKey(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// A trusted-LB id and a custom rule's host (or fingerprint) are keys of maps,
// and `default` there was the map's second default: nginx refused the whole
// configuration ("duplicate default map parameter").  The admin's forms let
// the id through, and config.yml is not validated on load, so the render
// writes each as a literal key whatever it is.
func TestReservedWordsRenderAsLiteralMapKeys(t *testing.T) {
	dir := t.TempDir()
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.TrustedLBExtra = []settings.TrustedLBExtra{
		{ID: "default", CIDRs: []string{"10.0.0.0/8"}, Header: "$http_x_client_ja4"},
		{ID: "edge-1", CIDRs: []string{"192.0.2.0/24"}, Header: "$http_x_client_ja4"},
	}
	s.Nginx.CustomRules = []settings.CustomRule{
		{ID: "cr1", Enabled: true, Action: settings.GeoActionCaptchaOnly, Conditions: []settings.CustomCondition{
			{Kind: settings.CustomCondHost, Values: []string{"default", "shop.example.com"}},
		}},
		{ID: "include", Enabled: true, Action: settings.GeoActionDeny, Conditions: []settings.CustomCondition{
			{Kind: settings.CustomCondJA4, Values: []string{"default", "t13d1516h2_*"}},
		}},
	}
	if err := Render(s, dir, "test"); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	httpInc, lbTrust := read("http.inc"), read("forward-auth-lbtrust.conf")

	for _, want := range []string{
		`    "\\default" $http_x_client_ja4;`, // the LB id keys the vendor -> header map
		`    "edge-1" $http_x_client_ja4;`,    // an ordinary id is written as before
		`    10.0.0.0/8 "default";`,           // a geo value is no key: as written
		`    "\\default" 1;`,                  // the rule's host line
		`    "shop.example.com" 1;`,
		`    "\\include" "deny";`, // the rule's id keys the action map
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc lacks %s", want)
		}
	}
	if !strings.Contains(lbTrust, `    "\\default" $http_x_client_ja4;`) {
		t.Error("forward-auth-lbtrust.conf does not escape the LB id")
	}
	// No map is left with the bare word in a key position beside its own
	// default line.
	for name, out := range map[string]string{"http.inc": httpInc, "forward-auth-lbtrust.conf": lbTrust} {
		for _, bad := range []string{`"default" $http_x_client_ja4;`, `    "default" 1;`, `    "include" "deny";`} {
			if strings.Contains(out, bad) {
				t.Errorf("%s still keys a map with %s", name, bad)
			}
		}
	}
}
