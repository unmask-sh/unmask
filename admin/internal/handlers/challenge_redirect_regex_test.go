package handlers

import (
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// TestChallengeSelfRedirectGuardAcceptsHostSites: challenge.js decides where to
// go after a pass.  Paths that ARE the challenge (direct access, the test
// pages) have no original page to return to and must go to "/" -- reloading
// them serves another challenge, so the visitor solves forever.
//
// Both site regexes in that file must therefore accept the same ids.  The one
// that parses the site out of the URL already allowed dots; the one guarding
// the redirect did not, so /unmask/challenge/shop.example.jp/ -- i.e. every
// real host name -- was treated as an ordinary page and reloaded itself.
func TestChallengeSelfRedirectGuardAcceptsHostSites(t *testing.T) {
	js, err := assets.Static.ReadFile("static/challenge.js")
	if err != nil {
		t.Fatalf("read challenge.js: %v", err)
	}
	src := string(js)

	// Pull both patterns straight out of the shipped file so the test tracks
	// the asset rather than a copy that can drift from it.
	extract := func(marker string) *regexp.Regexp {
		t.Helper()
		i := strings.Index(src, marker)
		if i < 0 {
			t.Fatalf("marker %q not found in challenge.js", marker)
		}
		// the JS literal reads /^\/unmask\/challenge...$/ -- strip the JS
		// escaping of "/" to get a Go-compatible pattern.
		end := strings.Index(src[i:], "$/")
		if end < 0 {
			t.Fatalf("could not delimit the pattern at %q", marker)
		}
		lit := src[i : i+end+1]
		return regexp.MustCompile(strings.ReplaceAll(lit, `\/`, `/`))
	}
	idRE := extract(`^\/unmask\/challenge\/(`)    // site parser (line ~16)
	guardRE := extract(`^\/unmask\/challenge(\/`) // redirect guard (passAndRedirect)

	for _, site := range []string{"shop.example.jp", "test.codezine.jp", "a.b.c.example.com", "shop", "test-1"} {
		path := "/unmask/challenge/" + site + "/"
		if !guardRE.MatchString(path) {
			t.Errorf("%s: redirect guard does not recognise the site-scoped page — it would reload itself (PoW loop)", path)
		}
		if !idRE.MatchString(path) {
			t.Errorf("%s: site id parser does not accept this host", path)
		}
	}
	// The bare and .html forms must keep matching the guard.
	for _, path := range []string{"/unmask/challenge/", "/unmask/challenge"} {
		if !guardRE.MatchString(path) {
			t.Errorf("%s must still be treated as direct challenge access", path)
		}
	}
	// An ordinary protected page must NOT be caught by the guard (it has a
	// real original page to return to).
	for _, path := range []string{"/articles/1", "/unmask/challengeXX/", "/shop/challenge/"} {
		if guardRE.MatchString(path) {
			t.Errorf("%s must not be treated as direct challenge access", path)
		}
	}
}
