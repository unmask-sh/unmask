package settings

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestChallengeJSInlineKey: challenge_js_inline is read from config.yml where
// the other challenge keys are, a site's own answer wins over the default's
// either way, a site that says what the default says goes back to following
// it, and an install that never set the key has none written for it.
func TestChallengeJSInlineKey(t *testing.T) {
	var s Settings
	const conf = `
challenge:
  default:
    challenge_js_inline: true
  sites:
    file.example:
      challenge_js_inline: false
    same.example:
      challenge_js_inline: true
`
	if err := yaml.Unmarshal([]byte(conf), &s); err != nil {
		t.Fatal(err)
	}
	if !s.Challenge.Default.IsChallengeJSInline() {
		t.Error("the default's challenge_js_inline: true was not read")
	}
	if s.Challenge.Resolve("file.example").IsChallengeJSInline() {
		t.Error("a site's own false did not win over the default's true")
	}
	if !s.Challenge.Resolve("other.example").IsChallengeJSInline() {
		t.Error("a site with no record does not follow the default")
	}
	if !ChallengeOverridesFor(s.Challenge, "file.example")["challenge_js_inline"] {
		t.Error("the site's own value is not marked as its own")
	}

	// Saying what the default says is not an answer of the site's own.
	same := SparsifyChallenge(s.Challenge.Shown("same.example"), s.Challenge.Default)
	if same.ChallengeJSInline != nil {
		t.Errorf("a site that says what the default says keeps the key: %v", *same.ChallengeJSInline)
	}
	kept := SparsifyChallenge(s.Challenge.Shown("file.example"), s.Challenge.Default)
	if kept.ChallengeJSInline == nil || *kept.ChallengeJSInline {
		t.Error("a site that differs from the default lost its answer")
	}

	// The reverse: off by default, on for one site.
	var r Settings
	if err := yaml.Unmarshal([]byte("challenge:\n  sites:\n    page.example:\n      challenge_js_inline: true\n"), &r); err != nil {
		t.Fatal(err)
	}
	if r.Challenge.Default.IsChallengeJSInline() || !r.Challenge.Resolve("page.example").IsChallengeJSInline() {
		t.Error("a site's own true did not win over the default's silence")
	}

	out, err := yaml.Marshal(Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "challenge_js_inline") {
		t.Error("an install that never set the key has it written out")
	}
}
