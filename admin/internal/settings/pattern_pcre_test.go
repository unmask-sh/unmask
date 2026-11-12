package settings

import (
	"strings"
	"testing"
)

// What Go's regexp compiles and nginx's PCRE refuses is refused on save, with
// a message that names the fragment; everything else these checks walk past
// stays accepted.  Each refusal was seen from a real nginx first (PCRE 1 and
// PCRE 2); TestNginxCompilesWhatCheckRegexAccepts in nginxconf asks one again.
func TestCheckRegexRefusesWhatPCREDoes(t *testing.T) {
	refused := []struct{ expr, names string }{
		// A character past \xFF as an escape.
		{`^/\x{3042}`, `\x{3042}`},
		{`^/\x{100}`, `\x{100}`},
		{`[\x{100}-\x{200}]`, `\x{100}`},
		{`\x{10FFFF}`, `\x{10FFFF}`},
		{`^/\400`, `\400`},
		{`\777`, `\777`},
		// A named group.
		{`^/(?P<uri>admin)/`, `(?P<uri>`},
		{`(?<foo>admin)`, `(?P<foo>`},
		{`a(b(?P<final_challenge>c))`, `$final_challenge`},
		// A range that starts at a class.
		{`[\w-.]+bot`, `\w-`},
		{`[^\w-.]`, `\w-`},
		{`[\d-z]`, `\d-`},
		{`[\s-\d]`, `\s-`},
		{`[\pL-z]`, `\pL-`},
		{`[\p{Greek}-z]`, `\p{Greek}-`},
		{`[[:alpha:]-z]`, `[:alpha:]-`},
		{`[a\d-z]`, `\d-`},
		{`[\d-\]]`, `\d-`},
		{`[]\w-.]`, `\w-`},
	}
	for _, c := range refused {
		err := CheckRegex(c.expr)
		if err == nil {
			t.Errorf("%s was accepted", c.expr)
			continue
		}
		if !strings.Contains(err.Error(), c.names) {
			t.Errorf("%s: the refusal does not name %s: %v", c.expr, c.names, err)
		}
	}
	// The byte-wise spelling the message offers is one nginx takes.
	if err := CheckRegex(`^/\x{3042}`); err == nil || !strings.Contains(err.Error(), `\xE3\x81\x82`) {
		t.Errorf(`the refusal of \x{3042} does not offer its bytes: %v`, err)
	}

	accepted := []string{
		`^/\x{41}`, `^/\x{ff}`, `^/\xff`, `\x41\x5a`, `[\x41-\x5a]`, `\377`, `\012`, `\12`,
		"^/あ", "[あ-ん]", `^/\xE3\x81\x82`,
		`(admin)`, `(?:a|b)`, `(?i)abc`, `(?i:abc)`, `(?s)a.b`, `(?U)a+`,
		`[\w-]`, `[\w.-]`, `[.\w-]`, `[-\d]`, `[^-\d]`, `[\d\-z]`, `[\w+-.]`, `[a-z-9]`, `[+--]`,
		`[[:alpha:]-]`, `[[:alpha:][:digit:]-]`, `[]a]`, `[^]a]`, `[\d-]x`,
		`\Q[\d-z]\E`, `\Q\x{3042}\E`, `a\Q`,
		`\\x{30}`, `[\\d-z]`, `\\\x{41}`, // an escaped backslash starts no escape
		`\pL+`, `\p{Greek}`, `\P{Lu}`, `[\p{L}\d]`, `\d+\.\d+`, `^/(wp-admin|wp-login\.php)`,
		`(?i)(curl|wget|python-requests)/[\d.]+`,
	}
	for _, expr := range accepted {
		if err := CheckRegex(expr); err != nil {
			t.Errorf("%s was refused: %v", expr, err)
		}
	}
}

// A pattern already in config.yml is not rewritten; the load log and `unmask
// doctor` say which one the next reload would stop on.
func TestPatternIssuesNameWhatPCRERefuses(t *testing.T) {
	var s Settings
	s.Nginx.BypassPaths.Paths = []BypassPath{{Path: `^/feed/[\w-.]+\.xml$`}, {Path: `^/ok/`}}
	issues := s.PatternIssues()
	if len(issues) != 1 || !strings.Contains(issues[0].String(), `\w-`) {
		t.Fatalf("issues = %v, want the one pattern with a range starting at \\w", issues)
	}
}
