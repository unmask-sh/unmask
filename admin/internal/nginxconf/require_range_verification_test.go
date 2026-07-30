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

	// Operator explicitly opted this pattern into UA-string rescue.
	var n settings.Nginx
	n.SearchBots.UpstreamUAEnabled = []string{pat}
	if EffectiveUpstreamUAOff(n)[pat] {
		t.Fatal("precondition: an explicit UA opt-in should keep the UA rescue on")
	}

	// The policy has to win: it is switched on precisely to stop
	// vendor-branded UA strings passing, and a row saved months earlier must
	// not carve a silent exception out of it.
	n.SearchBots.RequireRangeVerification = true
	if !EffectiveUpstreamUAOff(n)[pat] {
		t.Error("policy on: a range-backed pattern must not be rescued by its UA, " +
			"even when explicitly opted in -- a spoofed Googlebot would pass")
	}
	if got := UpstreamRVStates(n)[pat]; got != "ip" && got != "none" {
		t.Errorf("policy on: badge = %q, want the UA path shown as closed", got)
	}

	// Switching it back off must restore the explicit choice untouched: the
	// per-pattern lists are still in the config, merely outranked.
	n.SearchBots.RequireRangeVerification = false
	if EffectiveUpstreamUAOff(n)[pat] {
		t.Error("policy off: the operator's explicit UA opt-in should come back")
	}
}

// The policy must not touch patterns with no published range.  For those the
// UA string is the only rescue path, so refusing it would challenge the
// genuine crawler -- the exact accident this project exists to prevent.
func TestRequireRangeVerificationLeavesRangelessPatternsAlone(t *testing.T) {
	var n settings.Nginx
	n.SearchBots.RequireRangeVerification = true
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
		s.Nginx.SearchBots.UpstreamUAEnabled = []string{pat}
		s.Nginx.SearchBots.RequireRangeVerification = true
	})
	if containsPattern(on, pat) {
		t.Error("policy on: the range-backed UA is still in the rendered whitelist, " +
			"so native mode would pass a spoofed UA the tab says it blocks")
	}
	off := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.SearchBots.UpstreamUAEnabled = []string{pat}
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
