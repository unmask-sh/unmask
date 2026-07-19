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

func TestEffectiveRangeVerifiedPatterns(t *testing.T) {
	allOn := make([]string, 0, len(BypassIPGroups))
	for i := range BypassIPGroups {
		allOn = append(allOn, BypassIPGroups[i].ID)
	}

	// Operator saved on the release that shipped the new presets: everything
	// mapped is inverted.
	n := settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v0.1.7"}
	set := EffectiveRangeVerifiedPatterns(n)
	for _, pat := range []string{`Googlebot\/`, `bingbot`, `GPTBot`, `Amazonbot`, `DuckAssistBot`, `Perplexity-User`} {
		if !set[pat] {
			t.Errorf("all presets on: expected %q inverted", pat)
		}
	}
	if len(set) != len(UARangePresets) {
		t.Errorf("all presets on: got %d inverted patterns, want %d", len(set), len(UARangePresets))
	}

	// SeenVersion gate: an operator still on v0.1.6 has not reviewed the
	// v0.1.7 presets — patterns backed by them fall back to UA-only rescue,
	// while v0.1-era vendors stay inverted.
	n.SeenVersion = "v0.1.6"
	set = EffectiveRangeVerifiedPatterns(n)
	for _, pat := range []string{`Amazonbot`, `Applebot`, `DuckAssistBot`, `Perplexity-User`, `PerplexityUser`} {
		if set[pat] {
			t.Errorf("seenVer v0.1.6: expected %q NOT inverted (preset still NEW)", pat)
		}
	}
	for _, pat := range []string{`Googlebot\/`, `bingbot`, `DuckDuckBot`, `PerplexityBot\/`} {
		if !set[pat] {
			t.Errorf("seenVer v0.1.6: expected %q inverted", pat)
		}
	}

	// Union fallback: disabling ONE Google range preset reverts every Google
	// pattern to UA-only rescue (never "UA required with a hole in the
	// ranges"), and leaves other vendors inverted.
	partial := make([]string, 0, len(allOn))
	for _, id := range allOn {
		if id == "google-special" {
			continue
		}
		partial = append(partial, id)
	}
	n = settings.Nginx{BypassIPEnabledPresets: partial, SeenVersion: "v0.1.7"}
	set = EffectiveRangeVerifiedPatterns(n)
	for _, pat := range []string{`Googlebot\/`, `AdsBot-Google([^-]|$)`, `Google-Site-Verification`} {
		if set[pat] {
			t.Errorf("google-special off: expected %q to fall back to UA-only", pat)
		}
	}
	if !set[`bingbot`] || !set[`GPTBot`] {
		t.Error("google-special off: unrelated vendors must stay inverted")
	}

	// Dev/source build (unparseable SeenVersion) runs tip: nothing is NEW.
	n = settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v6f94983"}
	if set = EffectiveRangeVerifiedPatterns(n); !set[`Amazonbot`] {
		t.Error("dev build seenVer: expected v0.1.7 presets effective")
	}

	// No presets enabled: nothing inverted.
	n = settings.Nginx{SeenVersion: "v0.1.7"}
	if set = EffectiveRangeVerifiedPatterns(n); len(set) != 0 {
		t.Errorf("no presets: want empty inversion set, got %d", len(set))
	}
}
