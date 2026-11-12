package settings

import (
	"fmt"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CheckRegex compiles a pattern with Go's regexp; nginx compiles it with
// PCRE, in 8-bit mode.  The two agree on nearly everything an operator
// writes.  Where Go takes a pattern and PCRE does not, the page said "saved"
// and the next `nginx -t` refused the whole configuration.  pcreRefuses is
// the list of those shapes, each one checked against an nginx built with
// PCRE 1 and one built with PCRE 2 (TestNginxCompilesWhatCheckRegexAccepts
// asks a real nginx again):
//
//   - a character past \xFF written as an escape, \x{3042} or \777.  PCRE's
//     characters are bytes here ("character code point value in \x{} or \o{}
//     is too large").  The character itself is fine: it is its bytes.
//   - a named group, (?P<name>...).  nginx makes a variable of the name: one
//     of its own ("the duplicate "uri" variable") stops the configuration,
//     and any other name is a variable a match then overwrites.
//   - a range that starts at a class, [\w-.] or [[:alpha:]-z].  PCRE 2 calls
//     it an invalid range; PCRE 1, like Go, reads the hyphen as itself.
//
// Not covered: a Unicode script name newer than the host's PCRE (\p{Adlam}
// on PCRE 1), which no pattern for a path or a User-Agent has a use for.
func pcreRefuses(expr string, tree *syntax.Regexp) error {
	if name := namedGroup(tree); name != "" {
		return fmt.Errorf("the named group (?P<%s>...) is refused: nginx makes a variable of the name, $%s, which can collide with one of its own; write a plain group", name, name)
	}
	inClass := false  // between [ and its ]
	first := false    // at a class's first item, where ] is itself
	afterSet := false // the class item just read was a set: \d, \pL, [:alpha:]
	setStart := 0     // where that set began, for the message
	for i := 0; i < len(expr); {
		c := expr[i]
		n, set := 1, false
		switch {
		case c == '\\' && i+1 < len(expr):
			if !inClass && expr[i+1] == 'Q' {
				// \Q...\E is literal text (Go reads it outside a class only).
				end := strings.Index(expr[i+2:], `\E`)
				if end < 0 {
					return nil
				}
				i += 2 + end + 2
				continue
			}
			var v rune
			n, set, v = escapeAt(expr[i:])
			if v > 0xFF {
				hint := "write the character itself"
				if utf8.ValidRune(v) {
					var b strings.Builder
					for _, x := range []byte(string(v)) {
						fmt.Fprintf(&b, `\x%02X`, x)
					}
					hint += " (or its bytes, " + b.String() + ")"
				}
				return fmt.Errorf("%s is past \\xFF: nginx's regex engine matches bytes, not characters; %s", expr[i:i+n], hint)
			}
		case inClass && c == '[' && i+1 < len(expr) && expr[i+1] == ':':
			if end := strings.Index(expr[i+2:], ":]"); end >= 0 {
				n, set = 2+end+2, true
			}
		case inClass && c == ']' && !first:
			inClass, afterSet = false, false
			i++
			continue
		case !inClass && c == '[':
			inClass, first, afterSet = true, true, false
			i++
			if i < len(expr) && expr[i] == '^' {
				i++
			}
			continue
		}
		if inClass {
			if afterSet && c == '-' && i+1 < len(expr) && expr[i+1] != ']' {
				frag := expr[setStart:i]
				return fmt.Errorf("%s- is refused: inside [...] a range cannot start at %s, and nginx built with PCRE2 rejects the pattern; put the hyphen last in the class or write \\-", frag, frag)
			}
			afterSet, first = set, false
			if set {
				setStart = i
			}
		}
		i += n
	}
	return nil
}

// namedGroup returns the name of the first named capturing group, or "".
func namedGroup(re *syntax.Regexp) string {
	if re == nil {
		return ""
	}
	if re.Op == syntax.OpCapture && re.Name != "" {
		return re.Name
	}
	for _, sub := range re.Sub {
		if name := namedGroup(sub); name != "" {
			return name
		}
	}
	return ""
}

// escapeAt reads the escape at the start of s (s[0] is the backslash and
// there is a character after it): its length in bytes, whether it stands for
// a set of characters (\d \D \s \S \w \W \pL \p{Greek}), and for a hex or an
// octal escape the character it names.  s has passed Go's parser, so a
// malformed escape is not this function's to report.
func escapeAt(s string) (n int, set bool, v rune) {
	switch e := s[1]; {
	case strings.IndexByte("dDsSwW", e) >= 0:
		return 2, true, 0
	case e == 'p' || e == 'P':
		if len(s) > 2 && s[2] == '{' {
			if end := strings.IndexByte(s[3:], '}'); end >= 0 {
				return 3 + end + 1, true, 0
			}
			return 2, true, 0
		}
		if len(s) > 2 {
			return 3, true, 0
		}
		return 2, true, 0
	case e == 'x':
		if len(s) > 2 && s[2] == '{' {
			end := strings.IndexByte(s[3:], '}')
			if end < 0 {
				return 2, false, 0
			}
			x, err := strconv.ParseUint(s[3:3+end], 16, 32)
			if err != nil {
				return 3 + end + 1, false, 0
			}
			return 3 + end + 1, false, rune(x)
		}
		n = 2
		for n < len(s) && n < 4 && isHexDigit(s[n]) {
			n++
		}
		return n, false, 0
	case e >= '0' && e <= '7':
		// Up to three octal digits, as Go reads them.
		n = 1
		for n < len(s) && n < 4 && s[n] >= '0' && s[n] <= '7' {
			v = v*8 + rune(s[n]-'0')
			n++
		}
		return n, false, v
	}
	return 2, false, 0
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
