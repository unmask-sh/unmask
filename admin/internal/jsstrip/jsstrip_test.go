package jsstrip

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// TestLineComments: what goes and what stays, case by case.
func TestLineComments(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"a comment line goes", "a();\n// note\nb();\n", "a();\nb();\n"},
		{"an indented one too", "f(function(){\n  // note\n  a();\n});\n", "f(function(){\n  a();\n});\n"},
		{"blank lines go", "a();\n\n   \n\t\nb();\n", "a();\nb();\n"},
		{"a comment after code is cut off", "a(); // note\nb();\t// more\n", "a();\nb();\n"},
		{"the last line needs no newline", "a();\n// note", "a();\n"},
		{"code on the last line stays", "a();\nb() // note", "a();\nb()"},
		{"CRLF", "a();\r\n// note\r\nb(); // x\r\n", "a();\r\nb();\n"},
		{"the slashes of an address in a string", "var u = \"https://example.com/\"; // note\nvar v = 'a//b';\n", "var u = \"https://example.com/\";\nvar v = 'a//b';\n"},
		{"an escaped quote does not end the string", `var s = "a\"//b"; // c` + "\n", `var s = "a\"//b";` + "\n"},
		{"a string carried over a line", "var s = 'a\\\n// still the string\\\nb'; // c\n", "var s = 'a\\\n// still the string\\\nb';\n"},
		{"a regular expression with quotes in it", "s.replace(/[&<>\"']/g, f); // note\nvar t = \"x\"; // t\n", "s.replace(/[&<>\"']/g, f);\nvar t = \"x\";\n"},
		{"a slash inside a character class", "var r = /[/]\\/\\//; // note\n", "var r = /[/]\\/\\//;\n"},
		{"two slashes inside a character class", "x = y.replace(/[//]/g, ''); // note\n", "x = y.replace(/[//]/g, '');\n"},
		{"a regular expression after return", "function f(s){ return /^a\"b/.test(s); } // note\n", "function f(s){ return /^a\"b/.test(s); }\n"},
		{"a division is not one", "var a = b / c; // d / e\nvar f = (g) / h / 2; // i\n", "var a = b / c;\nvar f = (g) / h / 2;\n"},
		{"a division by a parenthesis", "var a = b / (c + d); // note\nvar e = f[0] / g; // h\n", "var a = b / (c + d);\nvar e = f[0] / g;\n"},
		{"a name that ends like a keyword", "var x = myreturn / 2; // note\nvar y = \"a\"; // b\n", "var x = myreturn / 2;\nvar y = \"a\";\n"},
		{"a keyword after another word", "x = typeof y / 2; // not a keyword before the slash\nvar s = \"q\"; // c\n", "x = typeof y / 2;\nvar s = \"q\";\n"},
		{"a template literal keeps its lines", "var t = `a\n// not a comment\n\n  b`; // note\nc();\n", "var t = `a\n// not a comment\n\n  b`;\nc();\n"},
		{"a substitution in a template", "var t = `a ${ f({k: \"}\"}) /* x */ + `in ${1}` } b\n// text`; // note\n", "var t = `a ${ f({k: \"}\"}) /* x */ + `in ${1}` } b\n// text`;\n"},
		{"a block comment stays, lines and all", "a(); /* one */ b();\n/* two\n// inside\n\n*/\nc(); // d\n", "a(); /* one */ b();\n/* two\n// inside\n\n*/\nc();\n"},
		{"a placeholder the server fills", "var f = /*__X__*/\"none\"; // note\n", "var f = /*__X__*/\"none\";\n"},
	} {
		got, ok := LineComments([]byte(c.in))
		if !ok {
			t.Errorf("%s: not read", c.name)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
		// What is left has nothing more to give.
		if again, ok := LineComments(got); !ok || !bytes.Equal(again, got) {
			t.Errorf("%s: a second pass changed it (ok=%v): %q", c.name, ok, again)
		}
	}
}

// TestLineCommentsGivesUp: a source the reader does not follow comes back as
// it was, byte for byte.
func TestLineCommentsGivesUp(t *testing.T) {
	for _, c := range []struct{ name, in string }{
		{"a string open at the end of its line", "var s = \"abc;\n// note\nb();\n"},
		{"a string open at the end of the source", "a();\nvar s = 'abc"},
		{"a template open at the end of the source", "var t = `a\n// b\n"},
		{"a substitution never closed", "var t = `a ${ b `;\n"},
		{"a block comment never closed", "a(); /* b\n// c\n"},
		{"a regular expression across a line", "var r = /ab\n// c\n/;\n"},
		{"a brace closed that was never opened", "a();\n}\n// note\n"},
		{"a parenthesis closed that was never opened", "a());\n// note\n"},
		{"a bracket left open", "var a = [1, 2;\n// note\n"},
		// The guess after ")" is "divides"; when it was a regular expression
		// with two slashes in a class, the cut would land inside it.
		{"a guess that would cut a regular expression", "if (a) /[//]/.test(b) && c();\n// note\n"},
		{"a backslash at the end of the source", "var s = 'a\\"},
	} {
		got, ok := LineComments([]byte(c.in))
		if ok {
			t.Errorf("%s: read as if it were sound: %q", c.name, got)
			continue
		}
		if string(got) != c.in {
			t.Errorf("%s: given up on, but not returned as it was: %q", c.name, got)
		}
	}
}

// TestChallengeScript: the script the daemon serves is one the reader
// follows, the prose is gone from it, and every line left is a line of the
// source, in order, with at most a comment cut off its end.
func TestChallengeScript(t *testing.T) {
	src, err := assets.Static.ReadFile("static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	out, ok := LineComments(src)
	if !ok {
		t.Fatal("challenge.js is not read with certainty: it would be served with its comments (see the package comment for what the reader gives up on)")
	}
	if len(out)*10 > len(src)*7 {
		t.Errorf("challenge.js went from %d to %d bytes: the comments are mostly still there", len(src), len(out))
	}
	in := strings.Split(string(src), "\n")
	next := 0
	for n, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		if s := strings.TrimSpace(line); s == "" || strings.HasPrefix(s, "//") {
			t.Fatalf("line %d of the served script is blank or a comment: %q", n+1, line)
		}
		found := false
		for ; next < len(in); next++ {
			if strings.HasPrefix(in[next], line) {
				// What was cut off is blanks and a comment, or nothing.
				if rest := strings.TrimSpace(in[next][len(line):]); rest == "" || strings.HasPrefix(rest, "//") {
					found = true
					next++
					break
				}
			}
		}
		if !found {
			t.Fatalf("line %d of the served script is not a line of challenge.js: %q", n+1, line)
		}
	}
	// The marks the daemon and the tests look for are code, not prose.
	for _, mark := range []string{"window.__unmaskStarted = true", "_bv_set_ok", "pow_seed"} {
		if !bytes.Contains(out, []byte(mark)) {
			t.Errorf("the served script lost %q", mark)
		}
	}

	// And it is still a script: node parses it, where there is a node.
	node, err := exec.LookPath("node")
	if err != nil {
		t.Log("no node on this machine: the syntax of the served script is not checked here (the browser tests run it)")
		return
	}
	f := filepath.Join(t.TempDir(), "challenge.served.js")
	if err := os.WriteFile(f, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if msg, err := exec.Command(node, "--check", f).CombinedOutput(); err != nil {
		t.Errorf("node does not parse the served script: %v\n%s", err, msg)
	}
}
