package settings

import (
	"fmt"
	"log"
	"sort"
)

// The proof-of-work difficulty is a count of leading zero bits, taken from
// PowDifficultyMin..PowDifficultyMax.  The settings page refuses a number
// outside that range.  One written into config.yml by hand is not applied
// either: ResolvedPowDifficulty answers PowDifficultyDefault for it, and the
// challenge page, the rendered nginx files and the verifier all read that
// answer, so they never disagree with each other -- only with the file.
const (
	PowDifficultyMin     = 8
	PowDifficultyMax     = 24
	PowDifficultyDefault = 18
)

// PowDifficultyIssue: one challenge record whose pow_difficulty is set to a
// number outside the range, and so runs at PowDifficultyDefault instead.
type PowDifficultyIssue struct {
	// Key is where the number sits in config.yml:
	// challenge.default.pow_difficulty, or challenge.sites.<site>.pow_difficulty.
	Key   string
	Value int
}

// String reads as the body of a log line or of a doctor warning.
func (i PowDifficultyIssue) String() string {
	return fmt.Sprintf("%s is %d, outside %d-%d, and is not applied: the proof-of-work there runs at the built-in %d bits",
		i.Key, i.Value, PowDifficultyMin, PowDifficultyMax, PowDifficultyDefault)
}

// PowDifficultyOutOfRange lists the records whose pow_difficulty is set but
// not applied: the default's first, then the sites' by name.  0 means "not
// set" (the record takes the default's number), and a site record that is
// switched off is not in force, so neither is listed.
//
// An operator who writes 30 to make the puzzle harder gets 18, the same as
// one who writes nothing, and nothing used to say so.  Load logs this list
// and `unmask doctor` warns with it.
func (c ChallengeConfig) PowDifficultyOutOfRange() []PowDifficultyIssue {
	outside := func(d int) bool {
		return d != 0 && (d < PowDifficultyMin || d > PowDifficultyMax)
	}
	var out []PowDifficultyIssue
	if outside(c.Default.PowDifficulty) {
		out = append(out, PowDifficultyIssue{Key: "challenge.default.pow_difficulty", Value: c.Default.PowDifficulty})
	}
	sites := make([]string, 0, len(c.Sites))
	for site, v := range c.Sites {
		if !v.Disabled && outside(v.PowDifficulty) {
			sites = append(sites, site)
		}
	}
	sort.Strings(sites)
	for _, site := range sites {
		out = append(out, PowDifficultyIssue{Key: "challenge.sites." + site + ".pow_difficulty", Value: c.Sites[site].PowDifficulty})
	}
	return out
}

// warnPowDifficultyRange logs what PowDifficultyOutOfRange lists, once per
// load of a config file.
func warnPowDifficultyRange(resolved string, s Settings) {
	for _, is := range s.Challenge.PowDifficultyOutOfRange() {
		log.Printf("unmask: config %s: %s. Set a number in range, or delete the key to silence this.", resolved, is)
	}
}
