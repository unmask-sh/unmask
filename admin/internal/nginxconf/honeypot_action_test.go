package nginxconf

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestResolveHoneypotAction: the native-mode resolver returns the per-preset /
// per-URL action override of the first matching honeypot rule ("" = inherit
// DefaultAction), honoring the same active-set logic (disabled presets, custom
// URL site filter) the renderer + forward-auth matcher use.  "wordpress" is a
// stable default-on preset (/wp-login\.php) so the cases do not depend on any
// opt-in group's enable state.
func TestResolveHoneypotAction(t *testing.T) {
	base := func(mut func(*settings.Nginx)) settings.Nginx {
		var n settings.Nginx
		n.SeenVersion = "v0.1" // baseline: nothing is treated as a NEW (skipped) preset
		if mut != nil {
			mut(&n)
		}
		return n
	}
	cases := []struct {
		name        string
		n           settings.Nginx
		uri         string
		site        string
		wantAction  string
		wantMatched bool
	}{
		{
			name:        "preset hit with per-preset override",
			n:           base(func(n *settings.Nginx) { n.Honeypot.PresetAction = map[string]string{"wordpress": "captcha_only"} }),
			uri:         "/wp-login.php",
			wantAction:  "captcha_only",
			wantMatched: true,
		},
		{
			name:        "preset hit, no override -> inherit (empty action)",
			n:           base(nil),
			uri:         "/wp-login.php",
			wantAction:  "",
			wantMatched: true,
		},
		{
			name:        "disabled preset -> no match",
			n:           base(func(n *settings.Nginx) { n.Honeypot.DisabledPresets = []string{"wordpress"} }),
			uri:         "/wp-login.php",
			wantAction:  "",
			wantMatched: false,
		},
		{
			name: "custom URL with action override",
			n: base(func(n *settings.Nginx) {
				n.Honeypot.URLs = []settings.HoneypotURL{{Path: "/my-custom-trap", Action: "deny"}}
			}),
			uri:         "/my-custom-trap",
			wantAction:  "deny",
			wantMatched: true,
		},
		{
			name: "custom URL bound to another site -> no match for empty site",
			n: base(func(n *settings.Nginx) {
				n.Honeypot.URLs = []settings.HoneypotURL{{Path: "/site-trap", Action: "captcha_only", Site: "other"}}
			}),
			uri:         "/site-trap",
			site:        "",
			wantAction:  "",
			wantMatched: false,
		},
		{
			name: "disabled custom URL -> no match",
			n: base(func(n *settings.Nginx) {
				n.Honeypot.URLs = []settings.HoneypotURL{{Path: "/off-trap", Action: "deny", Disabled: true}}
			}),
			uri:         "/off-trap",
			wantAction:  "",
			wantMatched: false,
		},
		{
			name:        "no honeypot rule matches",
			n:           base(nil),
			uri:         "/totally-normal-page",
			wantAction:  "",
			wantMatched: false,
		},
		{
			name:        "empty uri -> no match",
			n:           base(nil),
			uri:         "",
			wantAction:  "",
			wantMatched: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			action, matched := ResolveHoneypotAction(c.uri, c.site, c.n)
			if action != c.wantAction || matched != c.wantMatched {
				t.Errorf("ResolveHoneypotAction(%q, %q) = (%q, %v), want (%q, %v)",
					c.uri, c.site, action, matched, c.wantAction, c.wantMatched)
			}
		})
	}
}
