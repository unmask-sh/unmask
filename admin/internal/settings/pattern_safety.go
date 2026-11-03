package settings

import (
	"fmt"
	"regexp"
	"regexp/syntax"
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

// PatternMaxLen bounds the length of one pattern, in bytes.  PCRE's cost
// grows with the pattern too, and a rule's pattern is a line, not a file.
const PatternMaxLen = 1024

// repeatBoundedMax is the largest counted repetition, {n,m}, that may sit
// over an inner repetition: the ways the subject can be split are bounded by
// the count, so a small one is fine ((\d{1,3}\.){3} is an address), and a
// large one is the unbounded case under another name.
const repeatBoundedMax = 10

// CheckRegex compiles expr as the daemon does (Go's syntax) and refuses what
// nginx's engine would take exponential time on: a pattern longer than
// PatternMaxLen, and an unbounded repetition -- *, +, {n,} or a count over
// repeatBoundedMax -- whose operand itself repeats (*, +, ?, {n,m}).  The
// error names the subexpression, for the form's own error line.  An
// alternation of overlapping branches, (a|a)*, is the other classic shape
// and is not told apart here: this is the filter for the common one, not a
// proof.
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
	if bad := nestedRepeat(tree); bad != nil {
		return fmt.Errorf("nested repetition %s is refused: a repetition over a group that itself repeats can take nginx's regex engine exponential time on a request made to almost match it; write the inner part without its own repetition, or bound the outer count", bad)
	}
	return nil
}

// nestedRepeat returns the first unbounded repetition whose operand repeats,
// or nil.
func nestedRepeat(re *syntax.Regexp) *syntax.Regexp {
	if re == nil {
		return nil
	}
	if unboundedRepeat(re) {
		for _, sub := range re.Sub {
			if hasRepeat(sub) {
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

// hasRepeat: does the subtree repeat anywhere -- *, +, ?, {n,m}?  A ? counts:
// (a?)+ lets every iteration take the character or not, which is the same
// explosion.
func hasRepeat(re *syntax.Regexp) bool {
	if re == nil {
		return false
	}
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		return true
	case syntax.OpRepeat:
		if re.Min != re.Max || re.Max != 1 {
			return true
		}
	}
	for _, sub := range re.Sub {
		if hasRepeat(sub) {
			return true
		}
	}
	return false
}
