package main

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A row the settings page would not have taken is a WARN naming the list and
// the pattern; a file with nothing wrong is silent.
func TestCheckPatternIssues(t *testing.T) {
	s := settings.Settings{}
	got, _, addWarn, _ := newCaptures()
	checkPatternIssues(s, addWarn)
	if len(got.warn) != 0 {
		t.Errorf("nothing written: %+v, want silence", got)
	}

	s.Nginx.Honeypot.URLs = []settings.HoneypotURL{{Path: "^/ok$"}, {Path: "^/trap(("}}
	s.RateLimit.Zones = []settings.RateZone{{Name: "login", PathPatterns: []string{"(a+)+$"}}}
	got, _, addWarn, _ = newCaptures()
	checkPatternIssues(s, addWarn)
	if len(got.warn) != 2 {
		t.Fatalf("two rows are wrong: %+v, want two warnings", got)
	}
	for i, want := range [][]string{
		{"Rule patterns", `nginx.honeypot.urls: the pattern "^/trap(("`, "nginx -t"},
		{"Rule patterns", `rate_limit.zones[login].path_patterns: the pattern "(a+)+$"`, "nested repetition"},
	} {
		for _, w := range want {
			if !strings.Contains(got.warn[i], w) {
				t.Errorf("warning %d must carry %q, got: %s", i, w, got.warn[i])
			}
		}
	}
	if len(got.ok)+len(got.err) != 0 {
		t.Errorf("only warnings come out of this check: %+v", got)
	}
}
