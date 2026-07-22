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

// TestEffectiveUpstreamUAOffAuto pins the auto default (no explicit lists):
// identical to the v0.1.7 inversion, so an unsaved upgrade keeps its exact
// pre-decouple behavior — UA off while every backing preset is live, UA-only
// rescue otherwise (never "UA dropped AND range off").
func TestEffectiveUpstreamUAOffAuto(t *testing.T) {
	allOn := allPresetIDs()

	// Operator saved on the release that shipped the new presets: everything
	// mapped is UA-off (rescued by IP ranges).
	n := settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v0.1.7"}
	set := EffectiveUpstreamUAOff(n)
	for _, pat := range []string{`Googlebot\/`, `bingbot`, `GPTBot`, `Amazonbot`, `DuckAssistBot`, `Perplexity-User`} {
		if !set[pat] {
			t.Errorf("all presets on: expected %q UA-off", pat)
		}
	}
	if len(set) != len(UARangePresets) {
		t.Errorf("all presets on: got %d UA-off patterns, want %d", len(set), len(UARangePresets))
	}

	// SeenVersion gate: an operator still on v0.1.6 has not reviewed the
	// v0.1.7 presets — patterns backed by them stay on UA-only rescue,
	// while v0.1-era vendors are UA-off.
	n.SeenVersion = "v0.1.6"
	set = EffectiveUpstreamUAOff(n)
	for _, pat := range []string{`Amazonbot`, `Applebot`, `DuckAssistBot`, `Perplexity-User`, `PerplexityUser`} {
		if set[pat] {
			t.Errorf("seenVer v0.1.6: expected %q on UA rescue (preset still NEW)", pat)
		}
	}
	for _, pat := range []string{`Googlebot\/`, `bingbot`, `DuckDuckBot`, `PerplexityBot\/`} {
		if !set[pat] {
			t.Errorf("seenVer v0.1.6: expected %q UA-off", pat)
		}
	}

	// Union fallback: disabling ONE Google range preset reverts every Google
	// pattern to UA-only rescue (never "UA required with a hole in the
	// ranges"), and leaves other vendors UA-off.
	partial := make([]string, 0, len(allOn))
	for _, id := range allOn {
		if id == "google-special" {
			continue
		}
		partial = append(partial, id)
	}
	n = settings.Nginx{BypassIPEnabledPresets: partial, SeenVersion: "v0.1.7"}
	set = EffectiveUpstreamUAOff(n)
	for _, pat := range []string{`Googlebot\/`, `AdsBot-Google([^-]|$)`, `Google-Site-Verification`} {
		if set[pat] {
			t.Errorf("google-special off: expected %q to fall back to UA-only", pat)
		}
	}
	if !set[`bingbot`] || !set[`GPTBot`] {
		t.Error("google-special off: unrelated vendors must stay UA-off")
	}

	// Dev/source build (unparseable SeenVersion) runs tip: nothing is NEW.
	n = settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v6f94983"}
	if set = EffectiveUpstreamUAOff(n); !set[`Amazonbot`] {
		t.Error("dev build seenVer: expected v0.1.7 presets effective")
	}

	// No presets enabled: nothing UA-off.
	n = settings.Nginx{SeenVersion: "v0.1.7"}
	if set = EffectiveUpstreamUAOff(n); len(set) != 0 {
		t.Errorf("no presets: want empty UA-off set, got %d", len(set))
	}
}

// TestEffectiveUpstreamUAOffExplicit pins the explicit lists: they beat the
// auto default in both directions, and the two axes stay independent (the IP
// preset state no longer moves a pattern that has been saved explicitly).
func TestEffectiveUpstreamUAOffExplicit(t *testing.T) {
	allOn := allPresetIDs()

	// Explicit UA opt-in: the pattern keeps UA rescue although every preset
	// is live (the OR state — a spoofed UA passes and the operator said ok).
	n := settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v0.1.7"}
	n.SearchBots.UpstreamUAEnabled = []string{`Googlebot\/`}
	set := EffectiveUpstreamUAOff(n)
	if set[`Googlebot\/`] {
		t.Error("UpstreamUAEnabled: expected Googlebot to keep UA rescue")
	}
	if !set[`bingbot`] {
		t.Error("UpstreamUAEnabled: unrelated patterns must stay UA-off")
	}

	// Explicit disable: UA-off even with every preset inactive — the operator
	// chose it, so it does NOT fall back to UA-only rescue.
	n = settings.Nginx{SeenVersion: "v0.1.7"}
	n.SearchBots.UpstreamDisabled = []string{`Googlebot\/`}
	set = EffectiveUpstreamUAOff(n)
	if !set[`Googlebot\/`] {
		t.Error("UpstreamDisabled: expected Googlebot UA-off with presets inactive")
	}

	// Disabled wins over UAEnabled when both list the same pattern.
	n = settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v0.1.7"}
	n.SearchBots.UpstreamDisabled = []string{`GPTBot`}
	n.SearchBots.UpstreamUAEnabled = []string{`GPTBot`}
	if set = EffectiveUpstreamUAOff(n); !set[`GPTBot`] {
		t.Error("both lists: disabled must win")
	}
}

// TestUpstreamRVStates pins the 4-state badge classification and that the
// auto default never resolves to "none" (no-rescue is reachable only through
// explicit choices).
func TestUpstreamRVStates(t *testing.T) {
	allOn := allPresetIDs()

	n := settings.Nginx{BypassIPEnabledPresets: allOn, SeenVersion: "v0.1.7"}
	n.SearchBots.UpstreamUAEnabled = []string{`bingbot`}
	states := UpstreamRVStates(n)
	if got := states[`Googlebot\/`]; got != "ip" {
		t.Errorf("Googlebot: want ip, got %q", got)
	}
	if got := states[`bingbot`]; got != "or" {
		t.Errorf("bingbot (UA opt-in): want or, got %q", got)
	}

	// Presets inactive: auto lands on "ua"; explicit disable lands on "none".
	n = settings.Nginx{SeenVersion: "v0.1.7"}
	n.SearchBots.UpstreamDisabled = []string{`GPTBot`}
	states = UpstreamRVStates(n)
	if got := states[`Googlebot\/`]; got != "ua" {
		t.Errorf("Googlebot (presets off, auto): want ua, got %q", got)
	}
	if got := states[`GPTBot`]; got != "none" {
		t.Errorf("GPTBot (explicit off + presets off): want none, got %q", got)
	}

	// Auto never yields "none": with no explicit lists, every range-backed
	// pattern keeps at least one live rescue path whatever the preset state.
	for _, presets := range [][]string{nil, allOn, {"bing"}} {
		n = settings.Nginx{BypassIPEnabledPresets: presets, SeenVersion: "v0.1.7"}
		for pat, st := range UpstreamRVStates(n) {
			if st == "none" {
				t.Errorf("auto with presets=%v: pattern %q resolved to none", presets, pat)
			}
		}
	}
}
