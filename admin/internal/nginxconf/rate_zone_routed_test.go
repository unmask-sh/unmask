package nginxconf

import (
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A path-scoped rate zone counts a request whose URI a pattern matches as the
// client sent it, or as nginx routes it.
//
// The zone's patterns were held against $request_uri alone, the request
// line's URI as written, while nginx routes and serves by $uri: for a zone
// on ^/wp-login\.php, "/wp-login%2Ephp" was on no zone's paths and was
// served as /wp-login.php.  One character written as an escape, or a ".."
// segment, and the limit did not count the request.

func loginZone(s *settings.Settings) {
	s.RateLimit.Zones = []settings.RateZone{
		{Name: "login", PathPatterns: []string{`^/wp-login\.php`, `[?&]s=`}, RequestsPerMin: 5},
	}
}

func TestZonePathsAreHeldAgainstBothFormsOfTheURI(t *testing.T) {
	inc := renderHTTPInc(t, loginZone)
	for _, want := range []string{
		"map $request_uri $rl_login_match_sent {",
		`map "$uri$is_args$args" $rl_login_match_routed {`,
		`map "$rl_login_match_sent$rl_login_match_routed" $rl_login_match {`,
		"map $rl_login_match $rl_login_key {",
	} {
		if !strings.Contains(inc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	// Each form's map carries every pattern.
	for _, form := range []string{"$rl_login_match_sent {", "$rl_login_match_routed {"} {
		_, body, ok := strings.Cut(inc, form)
		if !ok {
			continue
		}
		body, _, _ = strings.Cut(body, "\n}")
		for _, pat := range []string{`"~*^/wp-login\\.php" 1;`, `"~*[?&]s=" 1;`} {
			if !strings.Contains(body, pat) {
				t.Errorf("the map of %s lacks the pattern %s", strings.TrimSuffix(form, " {"), pat)
			}
		}
	}
	if strings.Contains(inc, "map $request_uri $rl_login_match {") {
		t.Error("the zone's match is still read off $request_uri alone")
	}
}

// The routed form is read where the request arrives, in server.inc, so that
// it is the path the client asked for and not one a rewrite of the site's
// made of it: a map keeps the value of its first reading for the request.
func TestServerIncReadsTheZonesRoutedMatchFirst(t *testing.T) {
	srv := renderServerInc(t, loginZone)
	if !strings.Contains(srv, `set $unmask_rl_routed "$rl_login_match_routed";`) {
		t.Error("server.inc does not read the zone's routed match")
	}
	if none := renderServerInc(t, nil); strings.Contains(none, "$unmask_rl_routed") {
		t.Error("server.inc reads a routed match with no path-scoped zone to read it for")
	}
}

// The classic rate route names the mount by $uri, as the module's redirect
// does in compose mode: the daemon reads the zone off that path, and by
// $request_uri it was the path as the client spelled it.
func TestClassicRateRouteCarriesTheNormalizedPath(t *testing.T) {
	srv := renderServerInc(t, nil)
	if !strings.Contains(srv, "rewrite ^ /unmask/_rl$uri last;") {
		t.Error("the rate route is not rewritten by $uri")
	}
	if strings.Contains(srv, "/unmask/_rl$request_uri") {
		t.Error("the rate route still carries $request_uri")
	}
}

// TestNginxCountsAZonesPathHoweverItIsWritten asks a real nginx, by the
// request line as written, whether a request is on the zone's paths.
//
// Skipped unless UNMASK_TEST_NGINX and UNMASK_TEST_NGINX_MODULE are set:
// `make test-nginx-accepts` sets both.
func TestNginxCountsAZonesPathHoweverItIsWritten(t *testing.T) {
	bin, mod := os.Getenv("UNMASK_TEST_NGINX"), os.Getenv("UNMASK_TEST_NGINX_MODULE")
	if bin == "" || mod == "" {
		t.Skip("UNMASK_TEST_NGINX / UNMASK_TEST_NGINX_MODULE are not set")
	}
	ask := startNginxPaths(t, bin, mod,
		"rate_limit:\n  zones:\n    - name: login\n      requests_per_min: 5\n      path_patterns: ['^/wp-login\\.php', '[?&]s=', '^/files/%E3%81%82']\n",
		"$rl_login_match")
	on := 0
	for _, c := range []struct{ target, want, why string }{
		{"/wp-login.php", "1", "the path as the pattern writes it"},
		{"/wp-login.php?redirect_to=%2F", "1", "with a query"},
		{"/WP-LOGIN.PHP", "1", "in another case"},
		{"/wp-login%2Ephp", "1", "one character as an escape"},
		{"/wp%2Dlogin.php", "1", "another one"},
		{"/%77p-login.php", "1", "the first letter as an escape"},
		{"/x/../wp-login.php", "1", "behind a segment nginx resolves"},
		{"/x/%2e%2e/wp-login.php", "1", "the same, escaped"},
		{"//wp-login.php", "1", "behind a slash nginx merges"},
		{"/./wp-login.php", "1", "behind a segment nginx drops"},
		// A pattern that names the query, in either spelling of the path.
		{"/?s=shoes", "1", "the query the pattern names"},
		{"/search?page=2&s=shoes", "1", "further along the query"},
		{"/%73earch?s=shoes", "1", "under a path with an escape"},
		// A pattern written with an escape matches the URI as sent.
		{"/files/%E3%81%82.pdf", "1", "a pattern that names the escape as written"},
		// And nothing else is on the zone's paths.
		{"/", "0", "the front page"},
		{"/wp-admin/", "0", "another path"},
		{"/blog/wp-login.php", "0", "the name further down (the pattern is anchored)"},
		{"/page?next=/wp-login.php", "0", "the name in the query"},
		{"/search?page=2", "0", "a query without the argument"},
	} {
		got := ask(c.target)
		if got != c.want {
			t.Errorf("GET %s (%s): on the zone's paths = %q, want %q", c.target, c.why, got, c.want)
		}
		if got == "1" {
			on++
		}
	}
	if on != 14 {
		t.Errorf("%d of the requests are on the zone's paths, want 14: the table does not test what it says", on)
	}
}
