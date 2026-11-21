// Package jsstrip takes the line comments out of a JavaScript source.
//
// The challenge script is written to be read: four lines in ten are prose.
// Every challenge serve carries the script, most of them to clients that
// never run it, and a comment compresses to about a third of its size, not
// to nothing -- the prose was close to half of what went out.  The script is
// served without it.
//
// This is not a minifier.  A line that holds only a comment goes, so does a
// blank line, and a comment after code is cut off the end of its line; every
// other byte stays where it was, each line of code on a line of its own.
// Block comments stay too: there are few, and one that spans lines counts as
// a line break to the language.
//
// What makes a "//" a comment is where it stands, so the source is read
// through: strings, template literals, regular expressions and block comments
// are stepped over as units.  When the reading does not come out even -- a
// string open at the end of its line, a literal open at the end of the file,
// a brace closed that was never opened -- the source is one this reader does
// not follow, and LineComments returns it untouched: a script served whole is
// correct, and a script cut in the wrong place is a challenge nobody passes.
package jsstrip

// LineComments returns src without its line comments and blank lines, and
// true; or src itself and false when it could not be read with certainty.
func LineComments(src []byte) ([]byte, bool) {
	r := reader{src: src, out: make([]byte, 0, len(src))}
	if !r.run() {
		return src, false
	}
	return r.out, true
}

type reader struct {
	src []byte
	out []byte
	i   int

	lineOut int  // where the current line starts in out
	hasCode bool // the current line holds something other than blanks

	// The last byte of code that was not blank or comment, and the word it
	// ends when it ends one: what decides whether a "/" divides or opens a
	// regular expression.
	prev byte
	word []byte
	gap  bool // blanks, a newline or a comment since prev: a new word starts

	// Open brackets in code.  A source read correctly closes what it opens,
	// and never closes more: anything else is a reading gone wrong.
	braces, parens, squares int
	tmpl                    []int // for each "${" being read, the brace depth it opened at
}

// operand stands in prev for a literal just read: a value, after which a "/"
// divides.
const operand = ')'

func (r *reader) run() bool {
	for r.i < len(r.src) {
		c := r.src[r.i]
		switch {
		case c == '\n':
			r.newline()
			r.gap = true
			r.i++
		case c == ' ' || c == '\t' || c == '\r':
			r.out = append(r.out, c)
			r.gap = true
			r.i++
		case c == '/' && r.peek(1) == '/':
			r.lineComment()
			r.gap = true
		case c == '/' && r.peek(1) == '*':
			if !r.blockComment() {
				return false
			}
			r.gap = true
		case c == '/' && r.regexAllowed():
			if !r.regex() {
				return false
			}
		case c == '\'' || c == '"':
			if !r.quoted(c) {
				return false
			}
		case c == '`':
			r.code(c)
			r.i++
			if !r.template() {
				return false
			}
		case c == '{':
			r.braces++
			r.code(c)
			r.i++
		case c == '}':
			if n := len(r.tmpl); n > 0 && r.tmpl[n-1] == r.braces {
				// The end of a "${ ... }": back to the template's text.
				r.tmpl = r.tmpl[:n-1]
				r.code(c)
				r.i++
				if !r.template() {
					return false
				}
				continue
			}
			if r.braces == 0 {
				return false
			}
			r.braces--
			r.code(c)
			r.i++
		case c == '(' || c == '[':
			if c == '(' {
				r.parens++
			} else {
				r.squares++
			}
			r.code(c)
			r.i++
		case c == ')' || c == ']':
			n := &r.parens
			if c == ']' {
				n = &r.squares
			}
			if *n == 0 {
				return false
			}
			*n--
			r.code(c)
			r.i++
		default:
			r.code(c)
			r.i++
		}
	}
	// A last line without a newline is ended like the others.
	if !r.hasCode {
		r.out = r.out[:r.lineOut]
	}
	return len(r.tmpl) == 0 && r.braces == 0 && r.parens == 0 && r.squares == 0
}

func (r *reader) peek(n int) byte {
	if r.i+n < len(r.src) {
		return r.src[r.i+n]
	}
	return 0
}

// code writes one byte of code and remembers it for the next "/".
func (r *reader) code(c byte) {
	if isWord(c) {
		if r.gap || !isWord(r.prev) {
			r.word = r.word[:0]
		}
		r.word = append(r.word, c)
	}
	r.gap = false
	r.prev = c
	r.hasCode = true
	r.out = append(r.out, c)
}

// newline ends a line of code: a line that held nothing is dropped whole.
func (r *reader) newline() {
	if !r.hasCode {
		r.out = r.out[:r.lineOut]
	} else {
		r.out = append(r.out, '\n')
	}
	r.lineOut = len(r.out)
	r.hasCode = false
}

// inside writes a newline that is part of a literal or a block comment: the
// line it ends and the one it starts are kept as they are.
func (r *reader) inside() {
	r.out = append(r.out, '\n')
	r.lineOut = len(r.out)
	r.hasCode = true
}

// lineComment steps over a "//" comment, up to its newline.  After code, the
// blanks before it go with it.
func (r *reader) lineComment() {
	for r.i < len(r.src) && r.src[r.i] != '\n' {
		r.i++
	}
	if !r.hasCode {
		return
	}
	for n := len(r.out); n > r.lineOut && (r.out[n-1] == ' ' || r.out[n-1] == '\t' || r.out[n-1] == '\r'); n-- {
		r.out = r.out[:n-1]
	}
}

// blockComment copies a "/* ... */" as it is.
func (r *reader) blockComment() bool {
	r.hasCode = true
	r.out = append(r.out, '/', '*')
	r.i += 2
	for r.i < len(r.src) {
		c := r.src[r.i]
		if c == '*' && r.peek(1) == '/' {
			r.out = append(r.out, '*', '/')
			r.i += 2
			return true
		}
		if c == '\n' {
			r.inside()
		} else {
			r.out = append(r.out, c)
		}
		r.i++
	}
	return false
}

// quoted copies a '...' or "..." string.  It ends on its own line, unless a
// backslash carries it over.
func (r *reader) quoted(q byte) bool {
	r.hasCode = true
	r.out = append(r.out, q)
	r.i++
	for r.i < len(r.src) {
		c := r.src[r.i]
		switch c {
		case '\\':
			if !r.escape() {
				return false
			}
			continue
		case '\n':
			return false
		case q:
			r.out = append(r.out, c)
			r.i++
			r.prev = operand
			return true
		}
		r.out = append(r.out, c)
		r.i++
	}
	return false
}

// escape copies a backslash and what it escapes.
func (r *reader) escape() bool {
	if r.i+1 >= len(r.src) {
		return false
	}
	r.out = append(r.out, '\\')
	r.i++
	if r.src[r.i] == '\r' && r.peek(1) == '\n' {
		r.out = append(r.out, '\r')
		r.i++
	}
	if r.src[r.i] == '\n' {
		r.inside()
	} else {
		r.out = append(r.out, r.src[r.i])
	}
	r.i++
	return true
}

// template copies the text of a template literal, from after its backtick or
// after the "}" of a substitution, up to the closing backtick or into the
// next "${".
func (r *reader) template() bool {
	for r.i < len(r.src) {
		c := r.src[r.i]
		switch c {
		case '\\':
			if !r.escape() {
				return false
			}
			continue
		case '`':
			r.out = append(r.out, c)
			r.i++
			r.prev = operand
			return true
		case '$':
			if r.peek(1) == '{' {
				r.out = append(r.out, '$', '{')
				r.i += 2
				r.tmpl = append(r.tmpl, r.braces)
				r.prev = '{'
				return true
			}
		case '\n':
			r.inside()
			r.i++
			continue
		}
		r.out = append(r.out, c)
		r.i++
	}
	return false
}

// regex copies a regular expression literal and its flags.  A "/" inside a
// character class does not end it; a newline is never part of one.
func (r *reader) regex() bool {
	r.hasCode = true
	r.out = append(r.out, '/')
	r.i++
	class := false
	for r.i < len(r.src) {
		c := r.src[r.i]
		switch {
		case c == '\\':
			if r.peek(1) == '\n' || r.peek(1) == '\r' {
				return false
			}
			if !r.escape() {
				return false
			}
			continue
		case c == '\n':
			return false
		case c == '[':
			class = true
		case c == ']':
			class = false
		case c == '/' && !class:
			r.out = append(r.out, c)
			r.i++
			for r.i < len(r.src) && isWord(r.src[r.i]) {
				r.out = append(r.out, r.src[r.i])
				r.i++
			}
			r.prev = operand
			return true
		}
		r.out = append(r.out, c)
		r.i++
	}
	return false
}

// regexAllowed reports whether a "/" here opens a regular expression: after
// an operator, an opening bracket or one of the words an expression follows.
// After a value -- a name, a number, a closing bracket, a literal -- it
// divides.  The answer after ")" and "}" is a guess the language itself
// cannot settle without a parser; a wrong one leaves a literal open at the
// end of its line, and the source goes back untouched.
func (r *reader) regexAllowed() bool {
	switch {
	case r.prev == 0:
		return true
	case isWord(r.prev):
		switch string(r.word) {
		case "return", "typeof", "instanceof", "in", "of", "new", "delete",
			"void", "throw", "case", "do", "else", "yield", "await":
			return true
		}
		return false
	case r.prev == ')' || r.prev == ']' || r.prev == '}':
		return false
	}
	return true
}

func isWord(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
