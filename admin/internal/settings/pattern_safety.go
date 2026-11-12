package settings

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"unicode"
)

// The patterns the operator writes -- the UA filter, the paths, the honeypot
// URLs, the custom rules' conditions, the rate zones -- are checked here
// with Go's regexp and run by nginx, whose engine is PCRE.  Go's is linear
// in the input whatever the pattern; PCRE backtracks, and a repetition over
// a group that itself repeats, (a+)+ or (\w+\s?)+$, takes time exponential
// in the length of a subject that almost matches.  The subject of a UA or a
// path pattern is the request, which the visitor writes, so such a pattern
// is a way to burn a worker's CPU with one request each.  The save refuses
// the shape rather than trusting the compile.
//
// The explosion needs the subject to be splittable in more than one way.
// The everyday path shape ([^/]+/)* is not: each pass of the group runs to
// a slash the inner repetition cannot match, so a path splits one way only,
// at its slashes, and the match is linear.  That shape is accepted; see
// pinned.

// PatternMaxLen bounds the length of one pattern, in bytes.  PCRE's cost
// grows with the pattern too, and a rule's pattern is a line, not a file.
const PatternMaxLen = 1024

// repeatBoundedMax is the largest counted repetition, {n,m}, that may sit
// over an inner repetition: the ways the subject can be split are bounded by
// the count, so a small one is fine ((\d{1,3}\.){3} is an address), and a
// large one is the unbounded case under another name.
const repeatBoundedMax = 10

// CheckRegex compiles expr as the daemon does (Go's syntax), refuses the few
// shapes Go compiles and nginx's engine does not (pcreRefuses), and refuses
// what nginx's engine would take exponential time on: a pattern longer than
// PatternMaxLen, and an unbounded repetition -- *, +, {n,} or a count over
// repeatBoundedMax -- whose operand itself repeats (*, +, ?, {n,m}) in a way
// the subject can satisfy in more than one way.  The error names the
// subexpression, for the form's own error line.  An alternation of
// overlapping branches, (a|a)*, is the other classic shape and is not told
// apart here: this is the filter for the common one, not a proof.
func CheckRegex(expr string) error {
	if n := len(expr); n > PatternMaxLen {
		return fmt.Errorf("the pattern is %d bytes; %d at most", n, PatternMaxLen)
	}
	if _, err := regexp.Compile(expr); err != nil {
		return err
	}
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return err
	}
	// What Go compiles and nginx's PCRE does not (pattern_pcre.go).
	if err := pcreRefuses(expr, tree); err != nil {
		return err
	}
	if bad := nestedRepeat(tree); bad != nil {
		return fmt.Errorf("nested repetition %s is refused: a repetition over a group that itself repeats can take nginx's regex engine exponential time on a request made to almost match it; write the inner part without its own repetition, end each pass of the group with a separator the inner part cannot match (as in ([^/]+/)*), or bound the outer count", bad)
	}
	return nil
}

// nestedRepeat returns the first unbounded repetition whose operand repeats
// in a way that leaves the split of the subject open, or nil.
func nestedRepeat(re *syntax.Regexp) *syntax.Regexp {
	if re == nil {
		return nil
	}
	if unboundedRepeat(re) {
		for _, sub := range re.Sub {
			if openRepeat(sub) {
				return re
			}
		}
	}
	for _, sub := range re.Sub {
		if bad := nestedRepeat(sub); bad != nil {
			return bad
		}
	}
	return nil
}

// unboundedRepeat: *, +, {n,} or a count past repeatBoundedMax.
func unboundedRepeat(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus:
		return true
	case syntax.OpRepeat:
		return re.Max < 0 || re.Max > repeatBoundedMax
	}
	return false
}

// isRepeat: *, +, ?, {n,m}.  A ? counts: (a?)+ lets every iteration take
// the character or not, which is the same explosion.
func isRepeat(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		return true
	case syntax.OpRepeat:
		return re.Min != re.Max || re.Max != 1
	}
	return false
}

// openRepeat: does the subtree repeat anywhere in a way the subject can
// satisfy in more than one way?  Every repetition does, except one that is
// pinned by the element after it in the same sequence.
func openRepeat(re *syntax.Regexp) bool {
	if re == nil {
		return false
	}
	if isRepeat(re) {
		return true
	}
	if re.Op == syntax.OpConcat {
		for i, sub := range re.Sub {
			if e := uncapture(sub); isRepeat(e) {
				if i+1 < len(re.Sub) && pinned(e, re.Sub[i+1]) {
					continue
				}
				return true
			}
			if openRepeat(sub) {
				return true
			}
		}
		return false
	}
	for _, sub := range re.Sub {
		if openRepeat(sub) {
			return true
		}
	}
	return false
}

// pinned: rep repeats one character (a class, a literal, any character) or
// one literal string, and next -- the element that follows it in the same
// sequence -- begins with a character the repetition can never begin with.
// The repetition then has one extent only: it must run to where next
// begins, because stopping earlier leaves a character next cannot match
// and running further is impossible.  [^/]+ before a / is the shape; .* or
// \w* before a character they match is not.
func pinned(rep, next *syntax.Regexp) bool {
	if len(rep.Sub) != 1 {
		return false
	}
	first, ok := firstRunes(uncapture(rep.Sub[0]))
	if !ok {
		return false
	}
	after, ok := firstRunes(uncapture(next))
	if !ok {
		return false
	}
	return !rangesOverlap(first, after)
}

// firstRunes is the set of characters a literal, a character class or an
// any-character node can begin with, as the [lo, hi] pairs of a class.  ok
// is false for every other node (a group, an alternation, a repetition, an
// empty-width assertion), whose first character this does not work out.
func firstRunes(re *syntax.Regexp) (pairs []rune, ok bool) {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return nil, false
		}
		r := re.Rune[0]
		pairs = []rune{r, r}
		if re.Flags&syntax.FoldCase != 0 {
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				pairs = append(pairs, f, f)
			}
		}
		return pairs, true
	case syntax.OpCharClass:
		return re.Rune, len(re.Rune) > 0
	case syntax.OpAnyCharNotNL:
		return []rune{0, '\n' - 1, '\n' + 1, unicode.MaxRune}, true
	case syntax.OpAnyChar:
		return []rune{0, unicode.MaxRune}, true
	}
	return nil, false
}

// rangesOverlap: do two sets of [lo, hi] pairs share a character?
func rangesOverlap(a, b []rune) bool {
	for i := 0; i+1 < len(a); i += 2 {
		for j := 0; j+1 < len(b); j += 2 {
			if a[i] <= b[j+1] && b[j] <= a[i+1] {
				return true
			}
		}
	}
	return false
}

// uncapture looks through capturing groups: ([^/]+) before a / is pinned
// like [^/]+ is.
func uncapture(re *syntax.Regexp) *syntax.Regexp {
	for re != nil && re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	return re
}
