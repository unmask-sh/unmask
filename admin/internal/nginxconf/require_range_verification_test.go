package nginxconf

import (
	"slices"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// uaRescued: does pat land in the UA whitelist under n -- the same two steps
// the render runs (RangeVerifiedUA, then each crawler's own mode).
func uaRescued(n settings.Nginx, pat string) bool {
	white, _, _, _ := collectUpstreamPatternsByMode(n.SearchBots, RangeVerifiedUA(n))
	return slices.Contains(white, pat)
}

// Googlebot publishes its egress ranges, so its UA is a name tag rather than
// an ID.  RequireRangeVerification is the standing policy: for every
// range-backed pattern whose ranges are loaded, the UA rescue is off -- a
// crawler set to pass, group-wide or on its own, included.
func TestRequireRangeVerificationOutranksPass(t *testing.T) {
	const pat = `Googlebot\/`
	if RangeVerifiedPresetIDs(pat) == nil {
		t.Fatalf("%s is expected to be range-backed", pat)
	}

	// Operator set this crawler to pass on its own, with the vendor's ranges
	// wired in (the policy only closes the UA path when there is an address
	// list to verify against -- see RangeVerifiedUA).
	var n settings.Nginx
	n.BypassIPEnabledPresets = googleRangePresets
	n.SearchBots.UpstreamPatternMode = map[string]string{pat: "white"}
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
	if !uaRescued(n, pat) {
		t.Fatal("precondition: with the policy off, a crawler set to pass is rescued by its UA")
	}

	// The policy has to win: it is switched on precisely to stop
	// vendor-branded UA strings passing, and a row set months earlier must
	// not carve a silent exception out of it.
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(true)
	if uaRescued(n, pat) {
		t.Error("policy on: a range-backed pattern must not be rescued by its UA, " +
			"even when set to pass on its own -- a spoofed Googlebot would pass")
	}
	if !UpstreamRangeActive(n)[pat] {
		t.Error("policy on with presets live: the badge reports the preset, which is still enabled")
	}

	// Switching it back off restores the row's own setting untouched.
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
	if !uaRescued(n, pat) {
		t.Error("policy off: the crawler set to pass should be rescued by its UA again")
	}
}

// The policy must not touch patterns with no published range.  It switches how
// a rescued crawler is verified, and for these there is no address list to
// verify by -- so there is nothing for it to act on.  (Choosing not to rescue
// such a crawler at all is a separate decision with its own control: setting
// it to normal checks or stop.)
func TestRequireRangeVerificationLeavesRangelessPatternsAlone(t *testing.T) {
	var n settings.Nginx
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(true)
	verified := RangeVerifiedUA(n)

	for _, pat := range []string{
		`ChatWork LinkPreview`, // unmask's own supplement: no vendor ranges
		`Bytespider`,           // upstream, no published range
	} {
		if RangeVerifiedPresetIDs(pat) != nil {
			continue // gained a range mapping since; nothing to assert
		}
		if verified[pat] {
			t.Errorf("%s has no published range, so the policy must leave its UA rescue alone "+
				"(dropping it would block the real crawler)", pat)
		}
	}
	if !uaRescued(n, `Bytespider`) {
		t.Error("Bytespider passes by default (its group passes, it has no range), policy or not")
	}
}

// Rendered config follows the same resolution, so native mode enforces what
// the tab shows: the pattern leaves the $is_search_bot whitelist entirely.
func TestRequireRangeVerificationDropsPatternFromRenderedWhitelist(t *testing.T) {
	const pat = `Googlebot\/`
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassIPEnabledPresets = googleRangePresets
		s.Nginx.SearchBots.UpstreamPatternMode = map[string]string{pat: "white"}
		s.Nginx.SearchBots.RequireRangeVerification = settings.BoolPtr(true)
	})
	if containsPattern(on, pat) {
		t.Error("policy on: the range-backed UA is still in the rendered whitelist, " +
			"so native mode would pass a spoofed UA the tab says it blocks")
	}
	off := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassIPEnabledPresets = googleRangePresets
		s.Nginx.SearchBots.UpstreamPatternMode = map[string]string{pat: "white"}
		s.Nginx.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
	})
	if !containsPattern(off, pat) {
		t.Error("policy off: the crawler set to pass should render into the whitelist again")
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
// not ask here -- refusing a crawler outright is its own choice, made by
// setting it to normal checks or stop.
func TestRequireRangeVerificationKeepsUARescueWhenRangesAreNotLoaded(t *testing.T) {
	const pat = `Googlebot\/`

	// Policy on, presets never enabled.
	var n settings.Nginx
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(true)
	if !uaRescued(n, pat) {
		t.Error("no presets enabled: the UA rescue must stay, or the real crawler is challenged")
	}

	// Policy on, presets enabled but still NEW for this install (a fresh
	// upgrade has not acknowledged them yet, so they are not rendered).
	n.BypassIPEnabledPresets = googleRangePresets
	n.SeenVersion = "v0.1.0"
	if !RangePresetsActive(n, pat) { // still NEW-gated at this SeenVersion
		if !uaRescued(n, pat) {
			t.Error("presets still behind the NEW gate: the UA rescue must stay until they render")
		}
	}

	// Once they are live, the policy takes effect.
	n.SeenVersion = "v99.0.0"
	if uaRescued(n, pat) {
		t.Error("presets live: the policy should now close the UA path")
	}
}

// Turning the policy off puts a range-backed crawler that is set to pass back
// on its UA rescue, alongside its addresses (the OR state: a spoofed UA passes
// too, which is what turning the policy off accepts).  A crawler set to normal
// checks keeps only the address path.
func TestPolicyOffRestoresUARescueForPass(t *testing.T) {
	const pat = `Googlebot\/`
	var n settings.Nginx
	n.BypassIPEnabledPresets = googleRangePresets
	n.SeenVersion = "v99.0.0"
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(false)

	if !uaRescued(n, pat) {
		t.Error("policy off with presets live: a crawler following its passing group is rescued by its UA")
	}
	if !UpstreamRangeActive(n)[pat] {
		t.Error("policy off: the preset is enabled, so the badge stays green")
	}

	n.SearchBots.UpstreamPatternMode = map[string]string{pat: "none"}
	if uaRescued(n, pat) {
		t.Error("policy off + set to normal checks: the UA path must stay closed")
	}
	if !UpstreamRangeActive(n)[pat] {
		t.Error("policy off + set to normal checks: the badge tracks the preset, not this row's setting")
	}
}

// The legend states the badge as an absolute -- green means the preset is
// enabled, grey means it is not -- and separately describes what the policy
// switch does with a green-badged bot set to pass.  Pin both halves against
// the resolution so the copy and the behaviour cannot drift apart.
func TestBadgeAndPolicyMatchTheLegend(t *testing.T) {
	const pat = `Googlebot\/`
	mk := func(policy, presetOn, rowPasses bool) settings.Nginx {
		var n settings.Nginx
		n.SeenVersion = "v99.0.0"
		if presetOn {
			n.BypassIPEnabledPresets = googleRangePresets
		}
		n.SearchBots.RequireRangeVerification = settings.BoolPtr(policy)
		if rowPasses {
			n.SearchBots.UpstreamPatternMode = map[string]string{pat: "white"}
		} else {
			n.SearchBots.UpstreamPatternMode = map[string]string{pat: "none"}
		}
		return n
	}
	for _, c := range []struct {
		policy, preset, rowPasses bool
		wantUAPasses              bool
		why                       string
	}{
		// Legend: "On -- the address alone decides."
		{true, true, true, false, "policy on outranks the row set to pass"},
		{true, true, false, false, "policy on, row set to normal checks"},
		// Legend: "Off -- it passes on either its UA string or its address."
		{false, true, true, true, "policy off, row set to pass: the UA passes it too"},
		{false, true, false, false, "policy off, row set to normal checks: address only"},
		// Grey rows: the policy has no addresses to redirect the check to, so
		// the row's own setting is all there is.
		{true, false, true, true, "no addresses loaded, row set to pass"},
		{true, false, false, false, "no addresses loaded, row set to normal checks"},
		{false, false, true, true, "no addresses loaded, row set to pass"},
		{false, false, false, false, "no addresses loaded, row set to normal checks"},
	} {
		n := mk(c.policy, c.preset, c.rowPasses)
		if green := UpstreamRangeActive(n)[pat]; green != c.preset {
			t.Errorf("policy=%v preset=%v rowPasses=%v: badge green=%v, want %v -- "+
				"the legend says the badge reports the preset and nothing else",
				c.policy, c.preset, c.rowPasses, green, c.preset)
		}
		if uaPasses := uaRescued(n, pat); uaPasses != c.wantUAPasses {
			t.Errorf("policy=%v preset=%v rowPasses=%v: UA passes=%v, want %v (%s)",
				c.policy, c.preset, c.rowPasses, uaPasses, c.wantUAPasses, c.why)
		}
	}
}
