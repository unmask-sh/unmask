package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestRangeVerifiedUAInversionRender: with the vendor range presets enabled,
// range-verified crawler UA patterns are dropped from the rendered
// $is_search_bot map (their ranges carry the rescue via geo $is_bypass_ip),
// range-less crawlers keep their UA lines, and disabling one preset of a
// union vendor reverts that vendor to UA-only rescue.
func TestRangeVerifiedUAInversionRender(t *testing.T) {
	allOn := make([]string, 0, len(BypassIPGroups))
	for i := range BypassIPGroups {
		allOn = append(allOn, BypassIPGroups[i].ID)
	}

	// No range presets: pure UA rescue, note absent.
	off := renderHTTPInc(t, nil)
	for _, want := range []string{`"~*Googlebot\/" 1;`, `"~*bingbot" 1;`, `"~*GPTBot" 1;`} {
		if !strings.Contains(off, want) {
			t.Errorf("no presets: expected %q in $is_search_bot", want)
		}
	}
	if strings.Contains(off, "deliberately NOT listed here") {
		t.Error("no presets: inversion note must not render")
	}

	// Every preset on, operator current: inverted patterns leave the UA map,
	// their ranges are in the bypass geo, and the note explains the absence.
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassIPEnabledPresets = allOn
		s.Nginx.SeenVersion = "v0.1.7"
	})
	for _, gone := range []string{`"~*Googlebot\/" 1;`, `"~*bingbot" 1;`, `"~*GPTBot" 1;`, `"~*Amazonbot" 1;`, `"~*DuckAssistBot" 1;`, `"~*Applebot" 1;`} {
		if strings.Contains(on, gone) {
			t.Errorf("all presets on: %q must be dropped from $is_search_bot", gone)
		}
	}
	// Range-less crawlers keep the UA rescue.
	if !strings.Contains(on, `"~*Claude-Web" 1;`) {
		t.Error("all presets on: range-less crawler (Claude-Web) must keep its UA line")
	}
	if !strings.Contains(on, "deliberately NOT listed here") {
		t.Error("all presets on: inversion note missing")
	}
	// The vendor ranges themselves are folded into the bypass geo — including
	// a bare host IP from the amazonbot list (no CIDR suffix).
	for _, want := range []string{"192.178.4.0/27", "3.81.253.213"} {
		if !strings.Contains(on, want) {
			t.Errorf("all presets on: expected %q in geo $is_bypass_ip", want)
		}
	}

	// Union fallback: one Google preset off -> every Google pattern returns
	// to UA-only rescue; unrelated vendors stay inverted.
	partial := make([]string, 0, len(allOn))
	for _, id := range allOn {
		if id == "google-special" {
			continue
		}
		partial = append(partial, id)
	}
	mixed := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassIPEnabledPresets = partial
		s.Nginx.SeenVersion = "v0.1.7"
	})
	if !strings.Contains(mixed, `"~*Googlebot\/" 1;`) {
		t.Error("google-special off: Googlebot must fall back to the UA map")
	}
	if strings.Contains(mixed, `"~*bingbot" 1;`) {
		t.Error("google-special off: bingbot must stay inverted")
	}

	// Upgrade safety: presets enabled but the operator's last save predates
	// the v0.1.7 additions -> the new-vendor patterns stay on UA rescue.
	stale := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassIPEnabledPresets = allOn
		s.Nginx.SeenVersion = "v0.1.6"
	})
	if !strings.Contains(stale, `"~*Amazonbot" 1;`) {
		t.Error("seenVer v0.1.6: Amazonbot must stay on UA rescue (preset NEW)")
	}
	if strings.Contains(stale, `"~*Googlebot\/" 1;`) {
		t.Error("seenVer v0.1.6: Googlebot (v0.1-era presets) must be inverted")
	}

	// Explicit lists beat the auto default in both directions and decouple
	// the two axes: an UpstreamUAEnabled pattern keeps its UA line although
	// every preset is live (OR state), and an UpstreamDisabled pattern stays
	// out of the UA map although its presets are off (no UA-only fallback).
	explicit := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.BypassIPEnabledPresets = allOn
		s.Nginx.SeenVersion = "v0.1.7"
		s.Nginx.SearchBots.UpstreamUAEnabled = []string{`Googlebot\/`}
	})
	if !strings.Contains(explicit, `"~*Googlebot\/" 1;`) {
		t.Error("UpstreamUAEnabled: Googlebot must keep its UA line (OR state)")
	}
	if strings.Contains(explicit, `"~*bingbot" 1;`) {
		t.Error("UpstreamUAEnabled: unrelated bingbot must stay off the UA map")
	}
	explicitOff := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.SeenVersion = "v0.1.7"
		s.Nginx.SearchBots.UpstreamDisabled = []string{`Googlebot\/`}
	})
	if strings.Contains(explicitOff, `"~*Googlebot\/" 1;`) {
		t.Error("UpstreamDisabled + presets off: Googlebot must NOT fall back to the UA map")
	}
}
