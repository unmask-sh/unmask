package i18n

import (
	"regexp"
	"testing"
)

// Many of the catalog's strings carry markup and go into the admin's pages
// as they are (safeHTML).  The pages run under a policy that executes no
// inline handler, no javascript: link and no script without the response's
// nonce (handlers/csp_nonce.go), and a string cannot carry a nonce: markup
// that needs any of the three would render and then silently do nothing.
// The templates and the scripts have their own check
// (handlers/csp_templates_test.go); this is the catalog's.
func TestCatalogHoldsNothingTheScriptPolicyRefuses(t *testing.T) {
	refused := []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`(?i)<script\b`), "a <script> tag"},
		{regexp.MustCompile(`(?i)<[a-z][^<>]*\son[a-z]+\s*=`), "an inline on* handler"},
		{regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']?\s*javascript:`), "a javascript: link"},
	}
	for lang, catalog := range dict {
		if len(catalog) == 0 {
			t.Fatalf("the %s catalog is empty", lang)
		}
		for key, val := range catalog {
			for _, r := range refused {
				if r.re.MatchString(val) {
					t.Errorf("%s[%q] carries %s, which the admin's policy does not run:\n  %.160s", lang, key, r.what, val)
				}
			}
		}
	}
	// The patterns do match what they are for.
	for _, bad := range []string{`<a href="#" onclick="x()">y</a>`, `<SCRIPT>x</SCRIPT>`, `<a href='javascript:void(0)'>y</a>`} {
		hit := false
		for _, r := range refused {
			hit = hit || r.re.MatchString(bad)
		}
		if !hit {
			t.Errorf("%q passes the check", bad)
		}
	}
}
