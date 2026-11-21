package settings

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestChallengePageGzipKey: challenge_page_gzip is on where nothing is said,
// read from config.yml where the other challenge keys are; a site's own
// answer wins over the default's either way, a site that says what the
// default says goes back to following it, and an install that never set the
// key -- or set it to what unset means -- has none written for it.
func TestChallengePageGzipKey(t *testing.T) {
	var unset Settings
	if !unset.Challenge.Default.IsChallengePageGzip() || !unset.Challenge.Resolve("any.example").IsChallengePageGzip() {
		t.Fatal("an install that says nothing does not compress the page")
	}

	var s Settings
	const conf = `
challenge:
  default:
    challenge_page_gzip: false
  sites:
    packed.example:
      challenge_page_gzip: true
    same.example:
      challenge_page_gzip: false
`
	if err := yaml.Unmarshal([]byte(conf), &s); err != nil {
		t.Fatal(err)
	}
	if s.Challenge.Default.IsChallengePageGzip() {
		t.Error("the default's challenge_page_gzip: false was not read")
	}
	if !s.Challenge.Resolve("packed.example").IsChallengePageGzip() {
		t.Error("a site's own true did not win over the default's false")
	}
	if s.Challenge.Resolve("other.example").IsChallengePageGzip() {
		t.Error("a site with no record does not follow the default")
	}
	if !ChallengeOverridesFor(s.Challenge, "packed.example")["challenge_page_gzip"] {
		t.Error("the site's own value is not marked as its own")
	}

	// Saying what the default says is not an answer of the site's own.
	same := SparsifyChallenge(s.Challenge.Shown("same.example"), s.Challenge.Default)
	if same.ChallengePageGzip != nil {
		t.Errorf("a site that says what the default says keeps the key: %v", *same.ChallengePageGzip)
	}
	kept := SparsifyChallenge(s.Challenge.Shown("packed.example"), s.Challenge.Default)
	if kept.ChallengePageGzip == nil || !*kept.ChallengePageGzip {
		t.Error("a site that differs from the default lost its answer")
	}

	// The reverse: on by default (nothing said), off for one site.
	var r Settings
	if err := yaml.Unmarshal([]byte("challenge:\n  sites:\n    plain.example:\n      challenge_page_gzip: false\n"), &r); err != nil {
		t.Fatal(err)
	}
	if !r.Challenge.Default.IsChallengePageGzip() || r.Challenge.Resolve("plain.example").IsChallengePageGzip() {
		t.Error("a site's own false did not win over the default's silence")
	}

	// On the default, true is what unset means and is not kept; false is the
	// operator's answer and is.
	on := Settings{}
	on.Challenge.Default.ChallengePageGzip = BoolPtr(true)
	normalizeDefaults(&on)
	if on.Challenge.Default.ChallengePageGzip != nil {
		t.Error("the default's explicit true, which says nothing, was kept")
	}
	off := Settings{}
	off.Challenge.Default.ChallengePageGzip = BoolPtr(false)
	normalizeDefaults(&off)
	if off.Challenge.Default.ChallengePageGzip == nil || off.Challenge.Default.IsChallengePageGzip() {
		t.Error("the default's false, the operator's answer, was dropped")
	}
	out, err := yaml.Marshal(off)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "challenge_page_gzip: false") {
		t.Error("the operator's false is not written out")
	}

	out, err = yaml.Marshal(Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "challenge_page_gzip") {
		t.Error("an install that never set the key has it written out")
	}
}
