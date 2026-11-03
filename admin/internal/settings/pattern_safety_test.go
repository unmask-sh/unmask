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
