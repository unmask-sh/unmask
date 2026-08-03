package settings

import (
	"regexp"
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
