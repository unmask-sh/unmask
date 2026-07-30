package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Googlebot publishes its egress ranges, so its UA is a name tag rather than
// an ID.  The per-pattern default already drops such patterns from the UA
// whitelist -- but only while every backing preset happens to be enabled, and
// only for rows the operator has never saved, since saving the tab writes
// explicit entries that pin whatever was on screen.  RequireRangeVerification
// is the standing policy instead: for every range-backed pattern the UA
// rescue is off, full stop.
func TestRequireRangeVerificationOutranksAnExplicitUAOptIn(t *testing.T) {
	const pat = `Googlebot\/`
	if RangeVerifiedPresetIDs(pat) == nil {
		t.Fatalf("%s is expected to be range-backed", pat)
	}

	// Operator explicitly opted this pattern into UA-string rescue, with the
	// vendor's ranges wired in (the policy only closes the UA path when there
	// is an address list to verify against -- see EffectiveUpstreamUAOff).
	var n settings.Nginx
	n.BypassIPEnabledPresets = googleRangePresets
	n.SearchBots.UpstreamUAEnabled = []string{pat}
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
	if EffectiveUpstreamUAOff(n)[pat] {
		t.Fatal("precondition: an explicit UA opt-in should keep the UA rescue on")
	}

	// The policy has to win: it is switched on precisely to stop
	// vendor-branded UA strings passing, and a row saved months earlier must
	// not carve a silent exception out of it.
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(true)
	if !EffectiveUpstreamUAOff(n)[pat] {
		t.Error("policy on: a range-backed pattern must not be rescued by its UA, " +
			"even when explicitly opted in -- a spoofed Googlebot would pass")
	}
	if got := UpstreamRVStates(n)[pat]; got != "ip" && got != "none" {
		t.Errorf("policy on: badge = %q, want the UA path shown as closed", got)
	}

	// Switching it back off must restore the explicit choice untouched: the
	// per-pattern lists are still in the config, merely outranked.
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
	if EffectiveUpstreamUAOff(n)[pat] {
		t.Error("policy off: the operator's explicit UA opt-in should come back")
	}
}

// The policy must not touch patterns with no published range.  It switches how
// a rescued crawler is verified, and for these there is no address list to
// verify by -- so there is nothing for it to act on.  (Choosing not to rescue
// such a crawler at all is a separate decision with its own control: the
// per-pattern checkbox.)
func TestRequireRangeVerificationLeavesRangelessPatternsAlone(t *testing.T) {
	var n settings.Nginx
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(true)
	off := EffectiveUpstreamUAOff(n)

	for _, pat := range []string{
		`ChatWork LinkPreview`, // unmask's own supplement: no vendor ranges
		`Bytespider`,           // upstream, no published range
	} {
		if RangeVerifiedPresetIDs(pat) != nil {
			continue // gained a range mapping since; nothing to assert
		}
		if off[pat] {
			t.Errorf("%s has no published range, so the policy must leave its UA rescue alone "+
				"(dropping it would block the real crawler)", pat)
		}
	}
}

// Rendered config follows the same resolution, so native mode enforces what
// the tab shows: the pattern leaves the $is_search_bot whitelist entirely.
func TestRequireRangeVerificationDropsPatternFromRenderedWhitelist(t *testing.T) {
	const pat = `Googlebot\/`
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassIPEnabledPresets = googleRangePresets
		s.Nginx.SearchBots.UpstreamUAEnabled = []string{pat}
		s.Nginx.SearchBots.RequireRangeVerification = settings.BoolPtr(true)
	})
	if containsPattern(on, pat) {
		t.Error("policy on: the range-backed UA is still in the rendered whitelist, " +
			"so native mode would pass a spoofed UA the tab says it blocks")
	}
	off := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassIPEnabledPresets = googleRangePresets
		s.Nginx.SearchBots.UpstreamUAEnabled = []string{pat}
		s.Nginx.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
	})
	if !containsPattern(off, pat) {
		t.Error("policy off: the explicit UA opt-in should render into the whitelist again")
	}
}

// containsPattern looks for pat as a rendered map entry ("~*<pat>" 1;) rather
// than anywhere in the file: the pattern also appears in generated comments,
// which say nothing about whether the UA actually passes.
func containsPattern(conf, pat string) bool {
	return strings.Contains(conf, `"~*`+pat+`" 1;`)
}

// The policy closes the UA path only where there is an address list to verify
// against.  "Verify by address instead of by name" has to mean the addresses
// are actually loaded: with the vendor's presets not wired in (never enabled,
// or still behind the NEW gate after an upgrade) there is nothing to verify
// by, so the name stands.
//
// Collapsing this into "no rescue" would answer a question the operator did
// not ask here -- refusing a crawler outright is its own choice, made with
// the per-pattern checkbox.
func TestRequireRangeVerificationKeepsUARescueWhenRangesAreNotLoaded(t *testing.T) {
	const pat = `Googlebot\/`

	// Policy on, presets never enabled.
	var n settings.Nginx
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(true)
	if EffectiveUpstreamUAOff(n)[pat] {
		t.Error("no presets enabled: the UA rescue must stay, or the real crawler is challenged")
	}

	// Policy on, presets enabled but still NEW for this install (a fresh
	// upgrade has not acknowledged them yet, so they are not rendered).
	n.BypassIPEnabledPresets = googleRangePresets
	n.SeenVersion = "v0.1.0"
	if !RangePresetsActive(n, pat) { // still NEW-gated at this SeenVersion
		if EffectiveUpstreamUAOff(n)[pat] {
			t.Error("presets still behind the NEW gate: the UA rescue must stay until they render")
		}
	}

	// Once they are live, the policy takes effect.
	n.SeenVersion = "v99.0.0"
	if !EffectiveUpstreamUAOff(n)[pat] {
		t.Error("presets live: the policy should now close the UA path")
	}
}
