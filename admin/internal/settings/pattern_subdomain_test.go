package settings

import (
	"regexp"
	"testing"
)

// The subdomain mode (used by the admin-host allowlist) round-trips through the
// marker convention and renders to an anchored regex that matches the host and
// its children but never an appended attacker suffix.
func TestSubdomainPatternMode(t *testing.T) {
	stored := MakePatternWithMode("example.com", ModeSubdomain)
	if stored != "subdomain:example.com" {
		t.Fatalf("MakePatternWithMode = %q, want subdomain:example.com", stored)
	}
	if got := PatternModeOf(stored); got != ModeSubdomain {
		t.Errorf("PatternModeOf = %q, want subdomain", got)
	}
	if got := PatternText(stored); got != "example.com" {
		t.Errorf("PatternText = %q, want example.com", got)
	}
	if !IsLiteralPattern(stored) {
		t.Error("subdomain is a literal mode (no operator escaping)")
	}
	// Idempotent: cycling the mode must not stack markers.
	if again := MakePatternWithMode(stored, ModeSubdomain); again != stored {
		t.Errorf("MakePatternWithMode not idempotent: %q", again)
	}

	re := regexp.MustCompile(PatternRegex(stored))
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"admin.example.com", true},
		{"a.b.example.com", true},
		{"example.com.attacker.com", false},
		{"notexample.com", false},
	} {
		if got := re.MatchString(tc.host); got != tc.want {
			t.Errorf("PatternRegex(subdomain) vs %q = %v, want %v (re=%q)", tc.host, got, tc.want, PatternRegex(stored))
		}
	}
}
