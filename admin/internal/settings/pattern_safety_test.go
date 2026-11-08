package settings

import (
	"strings"
	"testing"
)

// The patterns nginx runs are checked here with Go's regexp, which is
// linear whatever the pattern; nginx's PCRE is not.  The save refuses the
// shape PCRE takes exponential time on -- a repetition over a group that
// itself repeats -- and a pattern past the length bound, and keeps taking
// the everyday ones.
func TestCheckRegexRefusesNestedRepetition(t *testing.T) {
	for _, ok := range []string{
		`^/wp-admin`,
		`(?i)bot|crawler|spider`,
		`^(\d{1,3}\.){3}\d{1,3}$`,
		`(a+)?b`,
		`^(?:.+\.)?example\.com$`,
		`^/api/v[0-9]+/`,
		`.*\.php$`,
		`(?i)^Mozilla/5\.0 \(compatible; [a-z]+bot/\d+\.\d+\)`,
		`(ab){2,5}c+`,
		// A repetition pinned by the separator after it splits the subject
		// one way only: these are linear in nginx's engine too.
		`^/([a-z]{2,3}/)?(luckyday|calendar|kyusei)/([^0-9/][^/]*/)*([0-9]{3}|1[0-8][0-9]{2}|2[1-9][0-9]{2}|[3-9][0-9]{3})([/?]|$)`,
		`^/([^/]+/)*[^/]*$`,
		`^/(([^/]+)/)+$`, // the capture around the repetition changes nothing
		`(\w+ )+$`,
		`^([a-z]+-)*[a-z]+$`,
		`^(\d+\.)*\d+$`,
		`(?i)^/(wp-[a-z]+/)+`,
		`(?i)([^a]*a)*`, // the class is folded too, so it still cannot match the a
		`((?:ab)+/)*`,   // a literal string repeats like a character does
		`(.*\n)*`,       // . does not match the newline that pins it
		`([^/]{2,}/)*`,
		`(a?b)*`,
	} {
		if err := CheckRegex(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`(a+)+$`,
		`(?:x*)*`,
		`(\w+\s?)+$`,
		`(a|b*)*`,
		`(a{2,})+`,
		`(a?)*`,
		`^(([a-z])+.)+[A-Z]([a-z])+$`,
		`(a+){2,50}`, // a count past the bound is the unbounded case
		`(?i)(\d+)+`, // the inline flag changes nothing
		`(`,          // not a regex at all
		"(" + strings.Repeat("a", PatternMaxLen) + ")", // too long
		// Not pinned: the separator is optional, missing, matched by the
		// repetition, or the repetition is over a group the subject can
		// tokenize in more than one way.
		`([^/]+/?)*`,
		`([^/]*)*`,
		`(a[^/]*)*`,
		`(.*/)*`,
		`([a-z]*a)*`,
		`(?i)([a-z]*A)*`, // folded: the A is an a
		`((aa|a)+/)*`,
		`((a|ab)+/)*`,
		`([^/]+/[^/]*)*`,
		`(\w+\b)*x`, // an assertion is not a character
	} {
		err := CheckRegex(bad)
		if err == nil {
			t.Errorf("%q accepted", bad)
			continue
		}
		if strings.Contains(bad, "+)+") || strings.Contains(bad, "*)*") {
			if !strings.Contains(err.Error(), "nested repetition") {
				t.Errorf("%q: the reason does not name the shape: %v", bad, err)
			}
		}
	}
	// The reason tells the operator about the accepted shape.
	if err := CheckRegex(`(\w+\s?)+$`); err == nil || !strings.Contains(err.Error(), "separator") {
		t.Errorf("the reason does not point at the separator form: %v", err)
	}
}

// NormalizeCustomCondition runs the same check on the UA and path
// conditions, which the AI's proposed rule also goes through.
func TestCustomConditionRefusesNestedRepetition(t *testing.T) {
	c := CustomCondition{Kind: CustomCondUA, Values: []string{`(a+)+b`}}
	if err := NormalizeCustomCondition(&c); err == nil || !strings.Contains(err.Error(), "nested repetition") {
		t.Errorf("UA condition: %v", err)
	}
	c = CustomCondition{Kind: CustomCondPath, Values: []string{`^/(\w+/?)+$`}}
	if err := NormalizeCustomCondition(&c); err == nil || !strings.Contains(err.Error(), "nested repetition") {
		t.Errorf("path condition: %v", err)
	}
	c = CustomCondition{Kind: CustomCondPath, Values: []string{`^/api/v\d+/`}}
	if err := NormalizeCustomCondition(&c); err != nil {
		t.Errorf("a plain path pattern: %v", err)
	}
}
