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
// History: the site-scoped preview used to live at /unmask/challenge/<site>/,
// which forced dotted host ids into the /challenge/ grammar in TWO regexes (the
// site-id parser and this redirect guard) -- and their drift over "may a site
// contain dots" was the 0.1.13 PoW loop.  The preview now lives under
// /unmask/test/site/<site>/, so the guard covers the whole /test/ subtree
// wholesale and /unmask/challenge/ is back to exactly one shape.  This test
// pins all three properties from the shipped asset.
func TestChallengeSelfRedirectGuardAcceptsHostSites(t *testing.T) {
	js, err := assets.Static.ReadFile("static/challenge.js")
	if err != nil {
		t.Fatalf("read challenge.js: %v", err)
	}
	src := string(js)

	// Pull the patterns straight out of the shipped file so the test tracks
	// the asset rather than a copy that can drift from it.
	extract := func(marker string) *regexp.Regexp {
		t.Helper()
		i := strings.Index(src, marker)
		if i < 0 {
			t.Fatalf("marker %q not found in challenge.js", marker)
		}
		// the JS literal reads /^\/unmask\/...$/ or /^.../.test(...) -- take
		// whichever delimiter comes FIRST after the marker, then strip the JS
		// escaping of "/" to get a Go-compatible pattern.
		endDollar := strings.Index(src[i:], "$/")   // /...$/ closing (keep "$")
		endTest := strings.Index(src[i:], "/.test") // /.../.test( closing
		var lit string
		switch {
		case endDollar >= 0 && (endTest < 0 || endDollar < endTest):
			lit = src[i : i+endDollar+1]
		case endTest >= 0:
			lit = src[i : i+endTest]
		default:
			t.Fatalf("could not delimit the pattern at %q", marker)
		}
		return regexp.MustCompile(strings.ReplaceAll(lit, `\/`, `/`))
	}
	idRE := extract(`^\/unmask\/test\/site\/(`)        // site parser (top of file)
	bareRE := extract(`^\/unmask\/challenge\/?$`)      // redirect guard: bare form
	subtreeRE := extract(`^\/unmask\/(admin\/)?test(`) // redirect guard: test subtree

	for _, site := range []string{"shop.example.jp", "test.codezine.jp", "a.b.c.example.com", "shop", "test-1"} {
		path := "/unmask/test/site/" + site + "/"
		if !subtreeRE.MatchString(path) {
			t.Errorf("%s: redirect guard does not recognise the site-scoped preview — it would reload itself (PoW loop)", path)
		}
		if !idRE.MatchString(path) {
			t.Errorf("%s: site id parser does not accept this host", path)
		}
	}
	// The whole test subtree is challenge-shaped: force-* flavors included.
	for _, path := range []string{"/unmask/test/force-pow", "/unmask/admin/test/force-captcha", "/unmask/test/"} {
		if !subtreeRE.MatchString(path) {
			t.Errorf("%s must be treated as a test page (no original page)", path)
		}
	}
	// The bare form must keep matching the guard.
	for _, path := range []string{"/unmask/challenge/", "/unmask/challenge"} {
		if !bareRE.MatchString(path) {
			t.Errorf("%s must still be treated as direct challenge access", path)
		}
	}
	// Site ids no longer belong under /challenge/ -- the route is gone, and
	// treating such a path as "the challenge itself" would hide a routing bug.
	if bareRE.MatchString("/unmask/challenge/shop.example.jp/") {
		t.Error("/unmask/challenge/<site>/ must no longer match the bare-challenge guard")
	}
	// An ordinary protected page must NOT be caught by any guard branch (it
	// has a real original page to return to).
	for _, path := range []string{"/articles/1", "/unmask/challengeXX/", "/shop/challenge/", "/testimonials/"} {
		if bareRE.MatchString(path) || subtreeRE.MatchString(path) {
			t.Errorf("%s must not be treated as direct challenge access", path)
		}
	}
}
