package nginxconf

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The tab-level default fills in a BLANK mode and nothing else.  This is the
// distinction from the default_action it replaces, which overrode each path's
// own mode (making the per-row picker decorative) and inherited from the
// unrelated rate-limit tab when unset -- so editing another tab could change
// what guards the admin login.  Pinned here: explicit always wins, blank
// follows the default, and an unset default is the shipped floor.
func TestResolveProtectedMode(t *testing.T) {
	cfg := func(def string) settings.ProtectedPathsConfig {
		return settings.ProtectedPathsConfig{DefaultMode: def}
	}
	for _, c := range []struct{ mode, def, want string }{
		{"pow", "captcha", "pow"},                    // explicit wins over the default
		{"captcha", "pow", "captcha"},                // ditto, both directions
		{"pow_then_captcha", "", "pow_then_captcha"}, // explicit with no default
		{"", "captcha", "captcha"},                   // blank follows the default
		{"", "pow", "pow"},                           //
		{"", "", ProtectedModeDefault},               // no default -> shipped floor
		{"nonsense", "captcha", "captcha"},           // an unusable stored value is a blank
		{"", "nonsense", ProtectedModeDefault},       // ... and so is an unusable default
	} {
		if got := ResolveProtectedMode(c.mode, cfg(c.def)); got != c.want {
			t.Errorf("mode=%q default=%q -> %q, want %q", c.mode, c.def, got, c.want)
		}
	}
}

// The composed rule set both wires read applies the default to blank rows and
// blank presets alike -- a preset ships blank precisely so one default moves it.
func TestEffectiveRulesFollowTheDefaultMode(t *testing.T) {
	var s settings.Settings
	s.Nginx.ProtectedPaths.EnabledPresets = []string{"unmask"}
	s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{
		{Path: `^/blank/`},                          // follows the default
		{Path: `^/pinned/`, Mode: ProtectedModePoW}, // keeps its own
	}
	byPattern := func(rs []ProtectedPathRule) map[string]string {
		m := map[string]string{}
		for _, r := range rs {
			m[r.Pattern] = r.Mode
		}
		return m
	}

	// No default set: everything blank lands on the floor.
	got := byPattern(EffectiveProtectedPathRules(s))
	if got[`^/blank/`] != ProtectedModeDefault || got[`^/unmask/admin/`] != ProtectedModeDefault {
		t.Errorf("with no default, blank row/preset should be %q, got row=%q preset=%q",
			ProtectedModeDefault, got[`^/blank/`], got[`^/unmask/admin/`])
	}
	if got[`^/pinned/`] != ProtectedModePoW {
		t.Errorf("an explicit row must keep its mode, got %q", got[`^/pinned/`])
	}

	// Set the default: the blank row AND the preset move; the pinned row does not.
	s.Nginx.ProtectedPaths.DefaultMode = ProtectedModeCaptcha
	got = byPattern(EffectiveProtectedPathRules(s))
	if got[`^/blank/`] != ProtectedModeCaptcha {
		t.Errorf("blank row should follow the default, got %q", got[`^/blank/`])
	}
	if got[`^/unmask/admin/`] != ProtectedModeCaptcha {
		t.Errorf("a preset with no pin should follow the default, got %q", got[`^/unmask/admin/`])
	}
	if got[`^/pinned/`] != ProtectedModePoW {
		t.Errorf("the default must not override an explicit row, got %q", got[`^/pinned/`])
	}

	// A pinned preset ignores the default too.
	s.Nginx.ProtectedPaths.PresetMode = map[string]string{"unmask": ProtectedModePoWThenCaptcha}
	got = byPattern(EffectiveProtectedPathRules(s))
	if got[`^/unmask/admin/`] != ProtectedModePoWThenCaptcha {
		t.Errorf("a pinned preset must keep its mode, got %q", got[`^/unmask/admin/`])
	}
}
