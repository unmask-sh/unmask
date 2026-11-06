package main

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A pow_difficulty outside the range is a WARN per record, naming the key,
// the number and what runs instead; in range, or not set, is silent.
func TestCheckPowDifficultyRange(t *testing.T) {
	s := settings.Settings{}
	got, _, addWarn, _ := newCaptures()
	checkPowDifficultyRange(s, addWarn)
	if len(got.warn) != 0 {
		t.Errorf("not set: %+v, want silence", got)
	}

	s.Challenge.Default.PowDifficulty = 20
	got, _, addWarn, _ = newCaptures()
	checkPowDifficultyRange(s, addWarn)
	if len(got.warn) != 0 {
		t.Errorf("in range: %+v, want silence", got)
	}

	s.Challenge.Default.PowDifficulty = 30
	s.Challenge.Sites = map[string]settings.ChallengeValues{
		"shop.example": {PowDifficulty: 4},
		"blog.example": {PowDifficulty: 12},
	}
	got, _, addWarn, _ = newCaptures()
	checkPowDifficultyRange(s, addWarn)
	if len(got.warn) != 2 {
		t.Fatalf("the default and one site are out of range: %+v, want two warnings", got)
	}
	for i, want := range [][]string{
		{"proof-of-work difficulty", "challenge.default.pow_difficulty is 30", "outside 8-24", "18 bits", "delete the key"},
		{"proof-of-work difficulty", "challenge.sites.shop.example.pow_difficulty is 4"},
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
