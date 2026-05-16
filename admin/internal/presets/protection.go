// presets: protection-mode preset definitions + apply helper.
//
// One-line abstraction over unmask's "challenge everyone / known browsers
// only / observe only" choices.  A simplification layer for the "which one
// should I pick?" moment right after install — after applying, the user can
// freely override individual fields (= the preset is a starting point).
package presets

import (
	"fmt"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Mode: 3 protection strengths.
type Mode string

const (
	// ModeStrict: challenge every UA.  Search / AI bots are reliably bypassed
	// via SearchBots + the official IP range.  Recommended default.
	ModeStrict Mode = "strict"
	// ModeBalanced: challenge only the known-browser group.  Generic tools
	// / scrapers and SaaS bots not in our preset pass through.
	ModeBalanced Mode = "balanced"
	// ModeMonitor: emit no challenges, only record events.  For the
	// post-install observation phase.  Implemented via settings.Challenge.ObserveOnly=true.
	ModeMonitor Mode = "monitor"
)

// IsValid: enum sanity check.
func (m Mode) IsValid() bool {
	switch m {
	case ModeStrict, ModeBalanced, ModeMonitor:
		return true
	}
	return false
}

// Apply: rewrite the relevant settings fields according to mode.
//
// Fields touched are limited:
//   - Nginx.ChallengeTargets.All (= challenge-every-UA on/off)
//   - Challenge.ObserveOnly       (= true only in monitor mode)
//
// Other fields (= JA4 verdict / honeypot / rate-limit zone / shared-feed
// etc.) involve too much per-user judgment, so the preset does not touch
// them.  Add a CLI flag or a separate preset if needed.
//
// Returns an error only when the mode is unknown.  Never fails on existing
// field values.
func Apply(s *settings.Settings, mode Mode) error {
	switch mode {
	case ModeStrict:
		s.Nginx.ChallengeTargets.All = true
		s.Challenge.ObserveOnly = false
	case ModeBalanced:
		s.Nginx.ChallengeTargets.All = false
		s.Challenge.ObserveOnly = false
	case ModeMonitor:
		// monitor keeps the detection logic itself equivalent to strict
		// (= evaluate every UA in the challenge classifier) and uses
		// ObserveOnly=true to suppress every challenge action.  This way the
		// dashboard shows exactly "how many challenges strict would have emitted."
		s.Nginx.ChallengeTargets.All = true
		s.Challenge.ObserveOnly = true
	default:
		return fmt.Errorf("unknown protection mode: %q (valid: strict / balanced / monitor)", mode)
	}
	return nil
}

// Describe: one-line description of a mode (= for CLI help / UI).
func Describe(m Mode) string {
	switch m {
	case ModeStrict:
		return "Challenge every UA — generic tools / scrapers (curl / python / wget) are stopped too.  SaaS bots not in our preset (SEO tools / search engines we don't know about) are also stopped, so you may need to whitelist their IPs / UAs individually."
	case ModeBalanced:
		return "Target only UAs matching the known_browser preset (Chrome / Safari / Firefox / Edge / Opera).  Generic tools / scrapers (curl / python / wget) and SaaS bots not in our preset (SEO tools / search engines we don't know about) pass through (= no whitelist needed for partner bots / regional crawlers)."
	case ModeMonitor:
		return "Keeps strict's classification logic but suppresses every challenge action, recording events only (= preview how many challenges strict would have fired before committing)."
	}
	return "(unknown)"
}

// Detect: infer the current Mode from the settings. Returns an empty
// string when the combination of fields doesn't map to a known mode
// (= the user has hand-tuned individual fields beyond what the presets
// touch). Useful for pre-selecting a radio in the wizard / settings UI.
func Detect(s settings.Settings) Mode {
	switch {
	case s.Nginx.ChallengeTargets.All && s.Challenge.ObserveOnly:
		return ModeMonitor
	case s.Nginx.ChallengeTargets.All && !s.Challenge.ObserveOnly:
		return ModeStrict
	case !s.Nginx.ChallengeTargets.All && !s.Challenge.ObserveOnly:
		return ModeBalanced
	}
	return ""
}
