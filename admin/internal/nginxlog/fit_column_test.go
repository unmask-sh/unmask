package nginxlog

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// What goes into a utf8mb4 column has to be UTF-8 and within the column's
// width in characters.  The User-Agent was cut at 255 bytes -- inside a
// character, where one straddles the cut -- and in forward-auth mode it is
// the request's header as sent, which need not be UTF-8 at all.
func TestFitColumn(t *testing.T) {
	cases := []struct {
		name, in string
		n        int
		want     string
	}{
		{"short and plain", "Mozilla/5.0", 255, "Mozilla/5.0"},
		{"exactly the width", strings.Repeat("a", 255), 255, strings.Repeat("a", 255)},
		{"past the width", strings.Repeat("a", 300), 255, strings.Repeat("a", 255)},
		// 254 bytes, then a three-byte character: a cut at 255 bytes falls
		// inside it.  The value is 255 characters, so it fits as it is.
		{"a character across byte 255", strings.Repeat("a", 254) + "あ", 255, strings.Repeat("a", 254) + "あ"},
		// The width is in characters: 300 three-byte characters are cut to 255
		// of them, not to 255 bytes.
		{"wide characters past the width", strings.Repeat("あ", 300), 255, strings.Repeat("あ", 255)},
		{"bytes that are not UTF-8", "curl/8\xff\xfe.0 \xe3\x81", 255, "curl/8.0 "},
		{"only such bytes", "\xff\xfe\xfd", 255, ""},
		{"a fingerprint too long for its column", strings.Repeat("t", 64), passJA4Width, strings.Repeat("t", passJA4Width)},
	}
	for _, c := range cases {
		got := fitColumn(c.in, c.n)
		if got != c.want {
			t.Errorf("%s: fitColumn(%q, %d) = %q, want %q", c.name, c.in, c.n, got, c.want)
		}
		if !utf8.ValidString(got) || utf8.RuneCountInString(got) > c.n {
			t.Errorf("%s: %q is not UTF-8 within %d characters", c.name, got, c.n)
		}
	}
}

// Both counters that keep a User-Agent keep one the column takes, whatever
// the request sent: the per-minute cookie reuse (also fed by forward-auth's
// check, from the request's header) and the per-day pass count.
func TestCountersKeepAUserAgentTheColumnTakes(t *testing.T) {
	r, _ := passReader(t)
	ua := strings.Repeat("a", 254) + "あ\xff tail"
	ja4 := strings.Repeat("j", 64)
	r.BumpCookieIP("default", "203.0.113.7", ja4, ua, "pow")
	r.bumpPass("default", "s.example", "203.0.113.7", ja4, ua, "1785943030.pow2.aaaa.0", "pow", true)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cookieIPBuckets) != 1 || len(r.passBuckets) != 1 {
		t.Fatalf("buckets: %d cookie, %d pass; want one of each", len(r.cookieIPBuckets), len(r.passBuckets))
	}
	check := func(what, gotUA, gotJA4 string) {
		t.Helper()
		if !utf8.ValidString(gotUA) || utf8.RuneCountInString(gotUA) > cookieIPUAMax {
			t.Errorf("%s: the User-Agent kept is not UTF-8 within %d characters: %q", what, cookieIPUAMax, gotUA)
		}
		if !strings.HasPrefix(gotUA, strings.Repeat("a", 254)+"あ") {
			t.Errorf("%s: the User-Agent kept lost what did fit: %q", what, gotUA)
		}
		if len(gotJA4) > passJA4Width {
			t.Errorf("%s: the fingerprint kept is %d bytes, the column takes %d", what, len(gotJA4), passJA4Width)
		}
	}
	for _, b := range r.cookieIPBuckets {
		check("cookie reuse", b.ua, b.ja4)
	}
	for _, b := range r.passBuckets {
		check("pass count", b.ua, b.ja4)
	}
}
