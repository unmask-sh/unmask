package db

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// What goes into a utf8mb4 column has to be UTF-8 and within the column's
// width in characters; a value that is neither is refused by MariaDB, and
// the transaction it rides in with it.
func TestFitColumn(t *testing.T) {
	cases := []struct {
		name, in string
		n        int
		want     string
	}{
		{"short and plain", "ua_target|own:curl", 255, "ua_target|own:curl"},
		{"exactly the width", strings.Repeat("a", 255), 255, strings.Repeat("a", 255)},
		{"past the width", strings.Repeat("a", 300), 255, strings.Repeat("a", 255)},
		// The width is in characters: a cut at 255 bytes would fall inside
		// the last one, and the value fits as it is.
		{"a character across byte 255", strings.Repeat("a", 254) + "あ", 255, strings.Repeat("a", 254) + "あ"},
		{"wide characters past the width", strings.Repeat("あ", 300), 255, strings.Repeat("あ", 255)},
		{"bytes that are not UTF-8", "curl/8\xff\xfe.0 \xe3\x81", 255, "curl/8.0 "},
		{"only such bytes", "\xff\xfe\xfd", 255, ""},
		{"no width", strings.Repeat("a", 300), 0, strings.Repeat("a", 300)},
		{"no width, bytes that are not UTF-8", "a\xffb", 0, "ab"},
	}
	for _, c := range cases {
		got := FitColumn(c.in, c.n)
		if got != c.want {
			t.Errorf("%s: FitColumn(%q, %d) = %q, want %q", c.name, c.in, c.n, got, c.want)
		}
		if !utf8.ValidString(got) || (c.n > 0 && utf8.RuneCountInString(got) > c.n) {
			t.Errorf("%s: %q is not UTF-8 within %d characters", c.name, got, c.n)
		}
	}
}
