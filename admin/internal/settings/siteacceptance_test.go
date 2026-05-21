package settings

import "testing"

func TestSiteAcceptance(t *testing.T) {
	auto := SiteAcceptanceConfig{}
	if auto.ResolvedMode() != SiteModeAuto {
		t.Error("empty mode should resolve to auto")
	}
	if auto.IsGhost("anything.example.com") {
		t.Error("auto mode: nothing is a ghost")
	}
	def := SiteAcceptanceConfig{Mode: "defined", Defined: []string{"shop.example.com"}}
	if def.ResolvedMode() != SiteModeDefined {
		t.Error("defined mode")
	}
	if def.IsGhost("shop.example.com") {
		t.Error("a Defined site is not a ghost")
	}
	if !def.IsGhost("evil.example.com") {
		t.Error("an unlisted site is a ghost in defined mode")
	}
	if def.IsGhost("") {
		t.Error("empty site is never a ghost")
	}
	if (SiteAcceptanceConfig{Mode: "weird"}).ResolvedMode() != SiteModeAuto {
		t.Error("unrecognized mode should resolve to auto")
	}
}
