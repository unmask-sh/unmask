package settings

import (
	"regexp"
	"strings"
)

// Operator patterns are regular expressions, and that is a trap the operator
// walks into by doing the obvious thing: pasting the value they want to block.
// A User-Agent pasted verbatim compiles, passes every check, and matches
// nothing -- "(X11; Linux x86_64)" is a capture group, so the pattern requires
// the UA with its parentheses removed.  Observed in production: a rule that
// read correctly in the config while the traffic it named walked past it.
//
// So a pattern may declare itself literal by carrying this marker.  The marker
// rides in the pattern string rather than in a parallel "mode" column: there
// are nine of these lists, the columns beside them are already parallel slices
// (title / enabled / created / updated / action), and every one of those is a
// place where a dropped entry silently shifts the rows below it -- twice today
// alone.  One string, one meaning, no alignment to keep.
//
// A regex that genuinely has to start with the marker text is written with its
// first character in a class: "[l]iteral:...".
const (
	// ContainsMarker: the text appears somewhere in the value.  The nginx maps
	// match unanchored, so this is what "paste the thing you want to block"
	// should have meant all along.
	ContainsMarker = "contains:"
	// ExactMarker: the value is this text and nothing else.
	ExactMarker = "exact:"
)

// PatternMode: how a stored pattern is read.
type PatternMode string

const (
	ModeRegex    PatternMode = "regex"
	ModeContains PatternMode = "contains"
	ModeExact    PatternMode = "exact"
)

// PatternModeOf: which reading a stored pattern declares.
func PatternModeOf(p string) PatternMode {
	switch {
	case strings.HasPrefix(p, ContainsMarker):
		return ModeContains
	case strings.HasPrefix(p, ExactMarker):
		return ModeExact
	}
	return ModeRegex
}

// IsLiteralPattern: does this pattern mean itself, character for character?
func IsLiteralPattern(p string) bool { return PatternModeOf(p) != ModeRegex }

// PatternText: what the operator typed, without the marker.  For display and
// for editing -- the UI shows the string they pasted, not its escaped form.
func PatternText(p string) string {
	p = strings.TrimPrefix(p, ContainsMarker)
	return strings.TrimPrefix(p, ExactMarker)
}

// PatternRegex: the expression to match with, in the one form both engines
// read.  A regex pattern passes through; a literal one is escaped, and an
// exact one is anchored as well.
//
// Escaping is by backslash (regexp.QuoteMeta), which is safe here in a way it
// is not in operator input: this output is generated, so it cannot carry the
// unbalanced backslash the input validator exists to reject.  The one thing
// QuoteMeta does not cover is the double quote, which would close the string
// the pattern is rendered inside in an nginx map.
func PatternRegex(p string) string {
	mode := PatternModeOf(p)
	if mode == ModeRegex {
		return p
	}
	q := strings.ReplaceAll(regexp.QuoteMeta(PatternText(p)), `"`, `\"`)
	if mode == ModeExact {
		return "^" + q + "$"
	}
	return q
}

// MakePatternWithMode: store this text under the given reading.  Idempotent,
// so a UI that cycles the modes does not stack markers.
func MakePatternWithMode(text string, mode PatternMode) string {
	text = PatternText(text)
	switch mode {
	case ModeContains:
		return ContainsMarker + text
	case ModeExact:
		return ExactMarker + text
	}
	return text
}
