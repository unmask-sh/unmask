package nginxconf

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestUARangePresetsPinnedToUpstream pins UARangePresets against the embedded
// crawler-user-agents.json: every key must exist as an upstream pattern (a
// typo or an upstream rename would silently leave that UA on UA-only rescue),
// its category must default to white (inverting a never-rescued pattern is a
// map bug), and every preset ID must resolve to a shipped BypassIPGroups
// entry.
func TestUARangePresetsPinnedToUpstream(t *testing.T) {
	groups := classify.UpstreamRescueList()
	if len(groups) == 0 {
		t.Fatal("UpstreamRescueList returned nothing; embed broken?")
	}
	patternCat := map[string]string{}
	for cat, entries := range groups {
		for _, e := range entries {
			patternCat[e.Pattern] = cat
		}
	}
	knownPreset := map[string]bool{}
	for i := range BypassIPGroups {
		knownPreset[BypassIPGroups[i].ID] = true
	}
	for pat, ids := range UARangePresets {
		cat, ok := patternCat[pat]
		if !ok {
			t.Errorf("UARangePresets key %q not found in crawler-user-agents.json patterns", pat)
			continue
		}
		if mode := classify.ResolveGroupMode(cat, nil); mode != classify.GroupModeWhite {
			t.Errorf("pattern %q resolves to category %q with default mode %q; inversion only makes sense for white", pat, cat, mode)
		}
		if len(ids) == 0 {
			t.Errorf("pattern %q has an empty preset list", pat)
		}
		for _, id := range ids {
			if !knownPreset[id] {
				t.Errorf("pattern %q references unknown preset ID %q", pat, id)
			}
		}
	}
}

func allPresetIDs() []string {
	ids := make([]string, 0, len(BypassIPGroups))
	for i := range BypassIPGroups {
		ids = append(ids, BypassIPGroups[i].ID)
	}
	return ids
}

// TestRangeVerifiedUA pins what the standing policy verifies by address: every
// range-backed pattern whose backing presets are all live, and nothing while
// the presets are off (never "UA dropped AND range off" by the policy's own
// hand).
func TestRangeVerifiedUA(t *testing.T) {
	allOn := allPresetIDs()

	// Every preset live: everything mapped is verified by its ranges.
	n := settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v0.1.7"}
	set := RangeVerifiedUA(n)
	for _, pat := range []string{`Googlebot\/`, `bingbot`, `GPTBot`, `Amazonbot`, `DuckAssistBot`, `Perplexity-User`} {
		if !set[pat] {
			t.Errorf("all presets on: expected %q verified by address", pat)
		}
	}
	if len(set) != len(UARangePresets) {
		t.Errorf("all presets on: got %d verified patterns, want %d", len(set), len(UARangePresets))
	}

	// SeenVersion does not gate: an operator still on v0.1.6 gets the newer
	// presets active exactly like a current save.
	n.SeenVersion = "v0.1.6"
	if set = RangeVerifiedUA(n); len(set) != len(UARangePresets) {
		t.Errorf("seenVer v0.1.6: got %d verified patterns, want %d (SeenVersion must not gate)", len(set), len(UARangePresets))
	}

	// Union fallback: disabling ONE Google range preset reverts every Google
	// pattern to its UA rescue (never "UA required with a hole in the
	// ranges"), and leaves other vendors verified.
	partial := make([]string, 0, len(allOn))
	for _, id := range allOn {
		if id == "google-special" {
			continue
		}
		partial = append(partial, id)
	}
	n = settings.Nginx{BypassIPEnabledPresets: partial, SeenVersion: "v0.1.7"}
	set = RangeVerifiedUA(n)
	for _, pat := range []string{`Googlebot\/`, `AdsBot-Google([^-]|$)`, `Google-Site-Verification`} {
		if set[pat] {
			t.Errorf("google-special off: expected %q to fall back to its UA rescue", pat)
		}
	}
	if !set[`bingbot`] || !set[`GPTBot`] {
		t.Error("google-special off: unrelated vendors must stay verified")
	}

	// An unparseable dev/source build is no exception -- presets stay effective.
	n = settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v6f94983"}
	if set = RangeVerifiedUA(n); !set[`Amazonbot`] {
		t.Error("dev build seenVer: expected presets effective")
	}

	// No presets enabled: nothing to verify against.
	n = settings.Nginx{SeenVersion: "v0.1.7"}
	if set = RangeVerifiedUA(n); len(set) != 0 {
		t.Errorf("no presets: want an empty set, got %d", len(set))
	}

	// The policy off: nothing is verified by address, whatever is live -- a
	// crawler set to pass passes on its UA string as well (the OR state).
	n = settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v0.1.7"}
	n.SearchBots.RequireRangeVerification = settings.BoolPtr(false)
	if set = RangeVerifiedUA(n); len(set) != 0 {
		t.Errorf("policy off: want an empty set, got %d", len(set))
	}
}

// How a row is set does not move the verified set: a crawler set to "none"
// or "black" has no UA rescue to replace, and the render and IsBot keep it
// off the rescue list on their own.  UpstreamUnrescued is that list for IsBot.
func TestRangeVerifiedIgnoresTheRowsOwnMode(t *testing.T) {
	allOn := allPresetIDs()
	for _, mode := range []string{"white", "none", "black"} {
		n := settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v0.1.7"}
		n.SearchBots.UpstreamPatternMode = map[string]string{`Googlebot\/`: mode}
		if !RangeVerifiedUA(n)[`Googlebot\/`] {
			t.Errorf("Googlebot set to %s: the policy still verifies it by address", mode)
		}
	}

	n := settings.Nginx{}
	n.SearchBots.UpstreamPatternMode = map[string]string{`GPTBot`: "black", `bingbot`: "none", `Applebot`: "white", `odd`: "maybe"}
	if got := UpstreamUnrescued(n); len(got) != 2 || got[0] != `GPTBot` || got[1] != `bingbot` {
		t.Errorf("UpstreamUnrescued = %q, want [GPTBot bingbot] (none and black, sorted)", got)
	}
}

// The badge reports one thing: is this bot's range preset enabled.  It must
// not move for any other reason -- the legend states it as an absolute, and a
// badge that also tracked the row's own setting is what made an earlier
// legend self-contradictory.
func TestBadgeFollowsThePresetAndNothingElse(t *testing.T) {
	allOn := allPresetIDs()
	const pat = `Googlebot\/`

	on := settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v99.0.0"}
	if !UpstreamRangeActive(on)[pat] {
		t.Error("preset enabled: the badge must be green")
	}
	off := settings.Nginx{SeenVersion: "v99.0.0"}
	if UpstreamRangeActive(off)[pat] {
		t.Error("preset disabled: the badge must be grey")
	}

	// Neither the policy nor how the row is set may move it.
	for _, policy := range []bool{true, false} {
		for _, mode := range []string{"", "white", "none", "black"} {
			n := settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v99.0.0"}
			n.SearchBots.RequireRangeVerification = settings.BoolPtr(policy)
			if mode != "" {
				n.SearchBots.UpstreamPatternMode = map[string]string{pat: mode}
			}
			if !UpstreamRangeActive(n)[pat] {
				t.Errorf("policy=%v row=%q: the preset is still enabled, so the badge must stay green",
					policy, mode)
			}
		}
	}

	// A pattern with no published range has no badge at all.
	if _, ok := UpstreamRangeActive(on)[`Bytespider`]; ok && RangeVerifiedPresetIDs(`Bytespider`) == nil {
		t.Error("a pattern with no published range should not be classified at all")
	}
}

// The NEW gate still counts as "not loaded": a preset ticked but not yet
// rendered for this install cannot verify anything, and showing it green would
// promise an address check that is not running.
func TestBadgeIsGreyWhilePresetsAreStillNewGated(t *testing.T) {
	n := settings.Nginx{BypassIPEnabledPresets: googleRangePresets, SeenVersion: "v0.1.0"}
	if !RangePresetsActive(n, `Googlebot\/`) && UpstreamRangeActive(n)[`Googlebot\/`] {
		t.Error("presets behind the NEW gate: the badge must be grey")
	}
}
