package settings

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Relocation of the challenge page's appearance from ChallengeValues to
// BrandingValues.
//
// Theme / CustomColors / ShowCredit describe what the challenge page LOOKS
// like, but they used to sit in the record that describes how the challenge
// BEHAVES.  Because a site's challenge record is inherited whole or owned whole
// (Resolve returns Sites[host] outright, never merging with Default), the
// theme tab could not store a theme for one site without minting a complete
// challenge-behaviour override for it -- seeded as a snapshot of Default.  Two
// consequences followed: sites showed up as having challenge overrides the
// operator never created, and once minted the snapshot stopped tracking
// Default, so a later change to, say, the PoW difficulty silently skipped every
// site that had ever been given a logo.
//
// Moving the three fields removes the cause rather than the symptom.  This file
// is the one-time bridge for config files written before the move: it reads the
// legacy keys straight from the YAML, so neither ChallengeValues nor
// BrandingValues carries a deprecated field.  Delete this file (and its call in
// Load / LoadFromYAML) once no supported install predates the change.
//
// Nothing is written back here -- Load must never Save (a save during load
// races the admin UI's own writes and has clobbered operator edits before).
// The relocated values simply live in memory until the operator's next save
// persists them in the new shape.

// legacyAppearance mirrors just enough of the pre-move file layout to find the
// three fields.  Everything else in the document is ignored, so this stays
// valid as the rest of the schema evolves.
type legacyAppearance struct {
	Challenge struct {
		Default legacyAppearanceValues            `yaml:"default"`
		Sites   map[string]legacyAppearanceValues `yaml:"sites"`
	} `yaml:"challenge"`
}

type legacyAppearanceValues struct {
	Theme        *string                         `yaml:"theme"`
	CustomColors map[string]ChallengeThemeColors `yaml:"custom_colors"`
	ShowCredit   *bool                           `yaml:"show_credit"`
}

func (l legacyAppearanceValues) empty() bool {
	return l.Theme == nil && l.CustomColors == nil && l.ShowCredit == nil
}

// graft copies whichever legacy fields are present onto a branding record.  A
// value already set on the branding side wins: a file that has been through a
// save in the new shape is authoritative, and re-reading the stale challenge
// copy beside it would undo the operator's most recent edit.
func (l legacyAppearanceValues) graft(b *BrandingValues) {
	if l.Theme != nil && b.Theme == "" {
		b.Theme = *l.Theme
	}
	if l.CustomColors != nil && b.CustomColors == nil {
		b.CustomColors = l.CustomColors
	}
	if l.ShowCredit != nil && b.ShowCredit == nil {
		b.ShowCredit = l.ShowCredit
	}
}

// relocateLegacyAppearance moves pre-move theme / colors / credit onto the
// branding records, then drops any challenge site override that the move has
// left indistinguishable from Default.
//
// That last step is the point.  Most legacy per-site challenge entries exist
// only because the operator picked a theme, and are otherwise a verbatim copy
// of Default; once the theme is gone they say nothing, yet their mere presence
// makes the site read as "has challenge overrides" and pins it to a snapshot.
// Removing them returns those sites to inheritance -- which is what the
// operator meant when they chose a theme and nothing else.
//
// raw is the config file body.  A parse failure leaves s untouched: the caller
// has already parsed the same bytes successfully into Settings, so a failure
// here means only that the legacy shape is absent.
func relocateLegacyAppearance(s *Settings, raw []byte) {
	var legacy legacyAppearance
	if yaml.Unmarshal(raw, &legacy) != nil {
		return
	}

	legacy.Challenge.Default.graft(&s.Branding.Default)

	for host, lv := range legacy.Challenge.Sites {
		if lv.empty() {
			continue
		}
		if s.Branding.Sites == nil {
			s.Branding.Sites = map[string]BrandingValues{}
		}
		// A site with a theme but no branding record still needs somewhere to
		// keep it, so create the record rather than drop the value.  Disabled
		// is deliberately not copied from the challenge entry: whether a site
		// overrides its appearance is now its own question.
		bv := s.Branding.Sites[host]
		lv.graft(&bv)
		s.Branding.Sites[host] = bv
	}

	pruneRedundantChallengeSites(s)
}

// pruneRedundantChallengeSites deletes challenge site records that carry
// nothing Default does not already say.  Disabled records are kept: Disabled
// means "inherit for now, but remember my values", and the operator can
// re-enable them from the settings page.
func pruneRedundantChallengeSites(s *Settings) {
	for host, cv := range s.Challenge.Sites {
		if cv.Disabled {
			continue
		}
		if challengeValuesEqual(cv, s.Challenge.Default) {
			delete(s.Challenge.Sites, host)
		}
	}
	if len(s.Challenge.Sites) == 0 {
		s.Challenge.Sites = nil
	}
}

// challengeValuesEqual compares two records field by field.  Written out rather
// than reflect.DeepEqual so that adding a field to ChallengeValues without
// considering it here is a compile error, not a silently weaker comparison that
// would start deleting overrides it no longer understands.
func challengeValuesEqual(a, b ChallengeValues) bool {
	if a.PowCookieValidSeconds != b.PowCookieValidSeconds ||
		a.CaptchaCookieValidSeconds != b.CaptchaCookieValidSeconds ||
		a.DebugRateLimitPer5Min != b.DebugRateLimitPer5Min ||
		a.ChallengeHTMLPath != b.ChallengeHTMLPath ||
		!boolEq(a.PublicTestPages, b.PublicTestPages) ||
		a.PublicTestPagesPassword != b.PublicTestPagesPassword ||
		!boolEq(a.PublicTestPagesSitePicker, b.PublicTestPagesSitePicker) ||
		a.PowDifficulty != b.PowDifficulty ||
		!boolEq(a.ObserveOnly, b.ObserveOnly) ||
		a.Disabled != b.Disabled ||
		a.CaptchaProvider != b.CaptchaProvider {
		return false
	}
	return true
}

// relocatedKeyRE matches the strict-probe complaint about a key this file
// deliberately consumes.
var relocatedKeyRE = regexp.MustCompile(
	`field (theme|show_credit|custom_colors) not found in type settings\.ChallengeValues`)

// withoutRelocatedAppearanceKeys drops the lines of a strict-probe error that
// name a relocated appearance key, returning "" when nothing else remains.
//
// The probe exists to tell an operator that a key in their file was thrown
// away.  For these three that is untrue -- relocateLegacyAppearance reads them
// straight from the YAML and applies them -- so reporting them would say a
// site's theme had been dropped when it is in force, and would send the
// operator looking for a mistake they did not make.  Everything else the probe
// finds still gets through.
//
// Goes away with the rest of this file.
func withoutRelocatedAppearanceKeys(msg string) string {
	lines := strings.Split(msg, "\n")
	kept := make([]string, 0, len(lines))
	for _, ln := range lines {
		if relocatedKeyRE.MatchString(ln) {
			continue
		}
		kept = append(kept, ln)
	}
	// A bare "yaml: unmarshal errors:" header with every detail line filtered
	// out is noise, not a finding.
	if len(kept) == 1 && strings.HasSuffix(strings.TrimSpace(kept[0]), "unmarshal errors:") {
		return ""
	}
	return strings.Join(kept, "\n")
}
