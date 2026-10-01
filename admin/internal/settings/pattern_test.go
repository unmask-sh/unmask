package settings

import (
	"regexp"
	"strings"
	"testing"
)

// The whole point: a value pasted as a literal has to match itself.  Pasting a
// UA as a regex is the trap -- "(X11; Linux x86_64)" is a capture group, so the
// pattern compiles, passes every check, and matches the UA with its
// parentheses removed, i.e. nothing.
func TestLiteralPatternMatchesTheTextItWasMadeFrom(t *testing.T) {
	for _, text := range []string{
		`Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36`,
		`OmvionLeadLake/1.0 (+https://omvion.org/crawler)`,
		`/wp-admin/admin-ajax.php?action=x`,
		`Some[Bot]{1} a|b ^c$ d.e`,
		`quote"inside`,
		`back\slash`,
	} {
		p := MakePatternWithMode(text, ModeContains)
		if !IsLiteralPattern(p) {
			t.Errorf("%q: not marked literal", text)
			continue
		}
		if got := PatternText(p); got != text {
			t.Errorf("%q: round trip gave %q", text, got)
		}
		rx := PatternRegex(p)
		re, err := regexp.Compile(rx)
		if err != nil {
			t.Errorf("%q -> %q: does not compile: %v", text, rx, err)
			continue
		}
		if !re.MatchString(text) {
			t.Errorf("%q -> %q: the escaped form does not match the text it came from", text, rx)
		}
		// It must not close the string it is rendered inside in an nginx map.
		for i := 0; i < len(rx); i++ {
			if rx[i] == '"' && (i == 0 || rx[i-1] != '\\') {
				t.Errorf("%q -> %q: carries an unescaped quote at %d", text, rx, i)
				break
			}
		}
	}
	// A pattern without the marker is a regex and passes through untouched --
	// existing rules keep meaning exactly what they meant.
	for _, rx := range []string{`X11; Linux x86_64`, `^Mozilla/5\.0`, `bot|crawler`} {
		if got := PatternRegex(rx); got != rx {
			t.Errorf("regex %q was rewritten to %q", rx, got)
		}
		if IsLiteralPattern(rx) {
			t.Errorf("%q was read as literal", rx)
		}
	}
	// Cycling the modes in the UI must not stack markers.
	if got := MakePatternWithMode(MakePatternWithMode("x", ModeContains), ModeExact); got != ExactMarker+"x" {
		t.Errorf("re-marking gave %q", got)
	}
	// Exact means the whole value: it matches the text and nothing around it.
	ex := MakePatternWithMode("Bytespider", ModeExact)
	re := regexp.MustCompile(PatternRegex(ex))
	if !re.MatchString("Bytespider") {
		t.Error("exact does not match its own text")
	}
	if re.MatchString("XBytespiderY") {
		t.Error("exact matched a value that merely contains the text")
	}
	// Contains does the opposite, which is what an unanchored nginx map does.
	co := regexp.MustCompile(PatternRegex(MakePatternWithMode("Bytespider", ModeContains)))
	if !co.MatchString("Mozilla/5.0 (compatible; Bytespider; x)") {
		t.Error("contains does not match a value it appears in")
	}
}

// A marker typed into the box on top of the one the form adds was stored
// twice, and a doubled exact marker matches only the text with one marker
// still on it -- an allowlist rule that rescued nothing.  Normalizing keeps
// the first marker as the reading and drops every repeat; a regex passes
// through untouched.
func TestNormalizePatternKeepsOneMarker(t *testing.T) {
	const text = "ExampleBot/1.0"
	markers := []string{ContainsMarker, ExactMarker, SubdomainMarker}
	for _, m := range markers {
		for n := 1; n <= 3; n++ {
			in := strings.Repeat(m, n) + text
			if got := NormalizePattern(in); got != m+text {
				t.Errorf("NormalizePattern(%q) = %q, want %q", in, got, m+text)
			}
		}
		// A marker alone is no pattern, however many times it is repeated.
		for n := 1; n <= 2; n++ {
			if got := NormalizePattern(strings.Repeat(m, n)); got != "" {
				t.Errorf("NormalizePattern(%q) = %q, want empty", strings.Repeat(m, n), got)
			}
		}
		// A different marker after the first is a repeat too: the first one
		// is the reading.
		for _, other := range markers {
			if other == m {
				continue
			}
			in := m + other + text
			if got := NormalizePattern(in); got != m+text {
				t.Errorf("NormalizePattern(%q) = %q, want %q", in, got, m+text)
			}
		}
	}
	// A regex is left alone, including one written to start with the marker
	// text (its first character in a class).
	for _, rx := range []string{`^Mozilla/5\.0`, "[" + ExactMarker[:1] + "]" + ExactMarker[1:] + text, ""} {
		if got := NormalizePattern(rx); got != rx {
			t.Errorf("regex %q was rewritten to %q", rx, got)
		}
	}
	// The point of it: the stored rule matches the UA it was written for.
	re := regexp.MustCompile(PatternRegex(NormalizePattern(ExactMarker + ExactMarker + text)))
	if !re.MatchString(text) {
		t.Errorf("normalized pattern %q does not match %q", re, text)
	}
}
