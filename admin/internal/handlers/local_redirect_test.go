package handlers

import "testing"

// isLocalRedirect is the single gate in front of every redirect that echoes a
// request-supplied path -- the observe-only bounce, the rebind bounce, the
// challenge return, the admin login return.  Six call sites, one function, so
// what it lets through is what all of them let through.
//
// It used to be three prefix checks: starts with "/", not "//", not "/\".  That
// reads as exhaustive and is not, because it inspects the string as written
// while the browser inspects the string as parsed, and those differ: a URL
// parser removes TAB, CR and LF from anywhere in the input before parsing.
// "/\t/evil.example" passes all three prefix checks and is then fetched as
// "//evil.example" -- protocol-relative, off-site.
//
// The same guard, in the same shape, was in challenge.js.  Both are fixed;
// this pins the Go half.
func TestIsLocalRedirect(t *testing.T) {
	offSite := []string{
		"//evil.example",
		"/\\evil.example",
		"/\\\\evil.example",
		"/\t/evil.example",  // TAB stripped by the parser -> "//evil.example"
		"/\n/evil.example",  // LF likewise
		"/\r/evil.example",  // CR likewise
		"/\t\\evil.example", // and the two tricks together
		"https://evil.example/",
		"http://evil.example/",
		"//evil.example/path?a=b",
		"javascript:alert(1)",
		"\\\\evil.example",
		"",
		"relative/path",
		"/\x00/evil.example",
	}
	for _, s := range offSite {
		if isLocalRedirect(s) {
			t.Errorf("isLocalRedirect(%q) = true; this reaches an off-site or unparseable target", s)
		}
	}

	// A guard that refuses everything would pass the list above and break the
	// product, so the ordinary shapes have to keep working.
	local := []string{
		"/",
		"/index.html",
		"/ja/",
		"/a/b/c?query=1&x=2",
		"/path#frag",
		"/path%20with%20escape",
		"/wp-admin",           // a scanner's path is still a local path
		"/single\\backslash",  // a backslash that is not in the authority position
		"/a?next=//evil.test", // off-site text inside the QUERY is not a redirect
	}
	for _, s := range local {
		if !isLocalRedirect(s) {
			t.Errorf("isLocalRedirect(%q) = false; a legitimate local path was refused", s)
		}
	}
}
