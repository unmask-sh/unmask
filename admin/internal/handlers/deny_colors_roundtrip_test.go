package handlers

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestDenyColorsSaveLoadRender exercises the full persistence loop for the deny
// page colors, which now live on the per-site appearance record
// (BrandingValues.DenyRate*/DenyBan*): a Settings is written by settings.Save,
// read back by settings.Load, resolved per site, and rendered through
// denyColorsRate/denyColorsBan + renderRateDenyC.
func TestDenyColorsSaveLoadRender(t *testing.T) {
	const (
		lightBg, lightText       = "#2244aa", "#ffeecc"
		darkBg, darkText         = "#112233", "#ddccbb"
		banLightBg, banLightText = "#0a3d62", "#f5f6fa" // ban carries its OWN colors
		siteBg, siteText         = "#abcdef", "#123456" // siteA's per-site rate override
	)

	var s settings.Settings
	s.Branding.Default.DenyRateColors = map[string]settings.ChallengeThemeColors{
		"light": {Bg: lightBg, Text: lightText},
		"dark":  {Bg: darkBg, Text: darkText},
	}
	s.Branding.Default.DenyBanColors = map[string]settings.ChallengeThemeColors{
		"light": {Bg: banLightBg, Text: banLightText},
	}
	// per-site override: siteA recolors the rate deny light differently.
	s.Branding.Sites = map[string]settings.BrandingValues{
		"siteA": {DenyRateColors: map[string]settings.ChallengeThemeColors{
			"light": {Bg: siteBg, Text: siteText},
		}},
	}

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(s, path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := settings.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	def := loaded.Branding.Default

	// 1. Default deny colors survive the yaml round-trip.
	if bg, text := def.DenyRateColorsFor("light"); bg != lightBg || text != lightText {
		t.Fatalf("default rate light = (%q,%q), want (%q,%q)", bg, text, lightBg, lightText)
	}
	if bg, text := def.DenyRateColorsFor("dark"); bg != darkBg || text != darkText {
		t.Fatalf("default rate dark = (%q,%q), want (%q,%q)", bg, text, darkBg, darkText)
	}

	// 2. per-site resolution: siteA owns its rate light; an unknown site -> Default.
	if bg, _ := loaded.Branding.Resolve("siteA").DenyRateColorsFor("light"); bg != siteBg {
		t.Fatalf("siteA rate light bg = %q, want %q", bg, siteBg)
	}
	if bg, _ := loaded.Branding.Resolve("other").DenyRateColorsFor("light"); bg != lightBg {
		t.Fatalf("unknown-site rate light bg = %q, want Default %q", bg, lightBg)
	}

	dc := denyColorsRate(def)
	br := settings.BrandingValues{SiteName: "ACME"}

	// 3. light/dark theme inject the right override.
	light := string(renderRateDenyC(br, "friendly", "light", "en", "/unmask", "", dc))
	mustContain(t, "light", light, lightBg, lightText)
	mustNotContain(t, "light", light, "ZgotmplZ")
	dark := string(renderRateDenyC(br, "friendly", "dark", "en", "/unmask", "", dc))
	mustContain(t, "dark", dark, darkBg, darkText)

	// 4. auto recolors PER OS scheme: light under :light, dark under :dark.
	auto := string(renderRateDenyC(br, "friendly", "auto", "en", "/unmask", "", dc))
	mustContain(t, "auto", auto, lightBg, lightText, darkBg, darkText,
		"prefers-color-scheme: light", "prefers-color-scheme: dark")
	mustNotContain(t, "auto", auto, "ZgotmplZ")

	// 4b. a light-ONLY override stays scoped to @media (prefers-color-scheme:
	//     light) so it does not bleed into auto's dark default (regression guard).
	lightOnly := string(renderRateDenyC(br, "friendly", "auto", "en", "/unmask", "", denyColors{LightBg: lightBg, LightText: lightText}))
	mustContain(t, "light-only auto", lightOnly, "prefers-color-scheme: light")

	// 5. ban deny carries its OWN colors; rate/ban do not leak into each other.
	if bg, text := def.DenyBanColorsFor("light"); bg != banLightBg || text != banLightText {
		t.Fatalf("default ban light = (%q,%q), want (%q,%q)", bg, text, banLightBg, banLightText)
	}
	ban := string(renderBanDenyC(br, "friendly", "light", "en", "/unmask", "", denyColorsBan(def)))
	mustContain(t, "ban", ban, banLightBg, banLightText)
	mustNotContain(t, "ban", ban, lightBg)
	mustNotContain(t, "rate", light, banLightBg)
}

func mustContain(t *testing.T, label, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("%s render missing %q", label, w)
		}
	}
}

func mustNotContain(t *testing.T, label, body string, unwanted ...string) {
	t.Helper()
	for _, u := range unwanted {
		if strings.Contains(body, u) {
			t.Errorf("%s render unexpectedly contains %q", label, u)
		}
	}
}
