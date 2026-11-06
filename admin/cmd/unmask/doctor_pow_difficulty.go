package main

import (
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// checkPowDifficultyRange: a pow_difficulty written into config.yml outside
// the range the proof-of-work takes is not applied -- the challenge page, the
// rendered nginx files and the verifier all run at the built-in default for
// it, so nothing breaks and nothing shows.  The settings page refuses such a
// number; this is for the file edited by hand or by a configuration manager,
// where an operator who raised the difficulty past the range would otherwise
// go on believing it took.  In range, or not set, is silent.
func checkPowDifficultyRange(s settings.Settings, addWarn func(t, m string)) {
	for _, is := range s.Challenge.PowDifficultyOutOfRange() {
		addWarn("proof-of-work difficulty", is.String()+". Set a number in range, or delete the key.")
	}
}
