package nginxconf

import (
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The patterns unmask ships are run by nginx against what the visitor sends
// -- the URL, the User-Agent -- exactly as an operator's own are, so they are
// held to the rule the settings page holds an operator to
// (settings.CheckRegex): no repetition over a group that itself repeats in a
// way the subject can satisfy in more than one way.  The sql-injection
// honeypot group shipped nine such patterns, and one request made for them
// held an nginx worker until its regex engine gave up.
//
// A pattern Go's regexp cannot parse (a lookahead, which nginx's engine
// reads) is outside what the check can see and is skipped.
func TestShippedPatternsPassTheOperatorCheck(t *testing.T) {
	n := 0
	check := func(where, p string) {
		t.Helper()
		if _, err := regexp.Compile(p); err != nil {
			return
		}
		n++
		if err := settings.CheckRegex(p); err != nil {
			t.Errorf("%s: %q: %v", where, p, err)
		}
	}
	for _, g := range HoneypotPresetGroups {
		for _, p := range g.Patterns {
			check("honeypot preset "+g.ID, p)
		}
	}
	for _, g := range BypassPathPresetGroups {
		for _, r := range g.Rules {
			check("bypass-path preset "+g.ID, r.Pattern)
		}
	}
	for _, g := range ProtectedPathPresetGroups {
		for _, r := range g.Rules {
			check("protected-path preset "+g.ID, r.Pattern)
		}
	}
	for _, g := range ChallengeTargetGroups {
		for _, p := range g.Patterns {
			check("challenge-target preset "+g.ID, p)
		}
	}
	for _, g := range JA4VerdictGroups {
		for _, r := range g.Rules {
			check("JA4 preset "+g.ID, r.Pattern)
		}
	}
	if n < 50 {
		t.Errorf("only %d shipped patterns were checked; the preset lists moved", n)
	}
}
