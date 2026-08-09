// enforcement_review.go: the "don't silently change enforcement on upgrade"
// hold.  A version bump can add a default-on ENFORCEMENT preset (JA4 verdict,
// honeypot path, challenge-target UA -- things that add a challenge/deny).  On
// an install running the "review" upgrade policy such a preset stays inert until
// the operator acknowledges the upgrade (advancing EnforcementReviewedVersion),
// so a growing operator base is not surprised by a tightened ruleset after a
// plain `dnf upgrade`.
//
// Deliberately asymmetric: RESCUE / bypass presets (search-bot rescue, bypass
// paths, redirect-exempt) are NEVER held -- loosening what passes must not wait
// on a review (CLAUDE.md: search bots always get through).  OPT-IN presets are
// never held either: turning one on is the operator's consent.
//
// Distinct from the removed seen_version opt-in gate: that gated EVERY new
// preset, in both directions, silently, on a version that drifted with every
// save.  This gates only tightening presets, only under an explicit policy, on a
// version that advances only on an explicit acknowledge, and surfaces what it
// holds (HeldEnforcementPresets -> settings banner + `unmask upgrade-review`).
package nginxconf

import "github.com/unmask-sh/unmask/admin/internal/settings"

// EnforcementHeld reports whether a default-on tightening preset added in
// addedIn must stay inert given this install's upgrade-review policy.  Callers
// pass it ONLY for tightening, default-on presets (never rescue/bypass, never an
// opt-in preset the operator explicitly enabled).
func EnforcementHeld(n settings.Nginx, addedIn string) bool {
	if n.ResolvedUpgradeReviewPolicy() != settings.UpgradeReviewReview {
		return false
	}
	// PresetIsNew treats an empty / unparseable reviewed version as "runs tip"
	// (nothing is new), so an existing config that never recorded one holds
	// nothing -- switching to "review" without a baseline is safe, not a sudden
	// blackout of every preset.
	return PresetIsNew(n.EnforcementReviewedVersion, addedIn)
}

// HeldPreset is one enforcement preset currently held pending upgrade review.
type HeldPreset struct {
	Category string // "ja4" | "challenge-target" | "honeypot"
	ID       string
	Label    string
	AddedIn  string
}

// HeldEnforcementPresets lists the default-on tightening presets held inert
// under the review policy -- exactly what the operator activates by
// acknowledging the upgrade.  Empty under the "apply" policy, or when nothing is
// newer than the reviewed version.  Drives the settings banner / review page and
// the `unmask upgrade-review` CLI.
func HeldEnforcementPresets(s settings.Settings) []HeldPreset {
	n := s.Nginx
	if n.ResolvedUpgradeReviewPolicy() != settings.UpgradeReviewReview {
		return nil
	}
	var out []HeldPreset

	// JA4 verdicts: default-on, opt-out (DisabledPresets).
	disV := toSet(n.JA4Verdicts.DisabledPresets)
	for _, g := range JA4VerdictGroups {
		if disV[g.ID] {
			continue
		}
		if EnforcementHeld(n, g.AddedIn) {
			out = append(out, HeldPreset{Category: "ja4", ID: g.ID, Label: g.Label, AddedIn: g.AddedIn})
		}
	}

	// Challenge targets: default-on, opt-out.
	disT := toSet(n.ChallengeTargets.DisabledPresets)
	for _, g := range ChallengeTargetGroups {
		if disT[g.ID] {
			continue
		}
		if EnforcementHeld(n, g.AddedIn) {
			out = append(out, HeldPreset{Category: "challenge-target", ID: g.ID, Label: g.Label, AddedIn: g.AddedIn})
		}
	}

	// Honeypot: only the default-on (non-opt-in) groups.  An opt-in group is
	// active only when the operator listed it -- that is consent, not a surprise.
	disH := toSet(n.Honeypot.DisabledPresets)
	for _, g := range HoneypotPresetGroups {
		if g.OptIn || disH[g.ID] {
			continue
		}
		if EnforcementHeld(n, g.AddedIn) {
			out = append(out, HeldPreset{Category: "honeypot", ID: g.ID, Label: g.Label, AddedIn: g.AddedIn})
		}
	}
	return out
}
