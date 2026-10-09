package nginxconf

import (
	"strings"
	"testing"
	"unicode/utf8"

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
			name: "custom URL with a contains: marker matches the literal anywhere",
			n: base(func(n *settings.Nginx) {
				n.Honeypot.URLs = []settings.HoneypotURL{{Path: "contains:/my-trap", Action: "deny"}}
			}),
			uri:         "/x/my-trap/y",
			wantAction:  "deny",
			wantMatched: true,
		},
		{
			name: "custom URL with an exact: marker does not match a longer path",
			n: base(func(n *settings.Nginx) {
				n.Honeypot.URLs = []settings.HoneypotURL{{Path: "exact:/only-this", Action: "deny"}}
			}),
			uri:         "/only-this/x",
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

// TestResolveHoneypotRuleNames: the resolved rule carries the name a ban's
// reason leads with -- a preset's name (its title without the examples), a
// custom row's title, or the pattern as typed when the row has none.
func TestResolveHoneypotRuleNames(t *testing.T) {
	var n settings.Nginx
	n.SeenVersion = "v0.1"
	n.Honeypot.URLs = []settings.HoneypotURL{
		{Path: "contains:/titled-trap", Title: "  Staging admin trap  ", Action: "deny"},
		{Path: "exact:/untitled-trap"},
	}
	for _, c := range []struct{ uri, wantRule, wantAction string }{
		{"/wp-login.php", "WordPress", ""},
		{"/x/titled-trap/y", "Staging admin trap", "deny"},
		{"/untitled-trap", "/untitled-trap", ""},
	} {
		m, ok := ResolveHoneypotRule(c.uri, "", n)
		if !ok || m.Rule != c.wantRule || m.Action != c.wantAction {
			t.Errorf("ResolveHoneypotRule(%q) = (%+v, %v), want rule %q action %q", c.uri, m, ok, c.wantRule, c.wantAction)
		}
	}
	if m, ok := ResolveHoneypotRule("/nothing-here", "", n); ok {
		t.Errorf("a URI no rule matches resolved to %+v", m)
	}
}

// A preset's name is how an operator finds the group on the honeypot tab from
// a ban's reason: the label's title, non-empty, unique across the groups, and
// kept short (32 characters) on purpose -- it leads every reason the group
// creates and must leave the probed host visible in the ban list's clamped
// cell.  A custom rule's title has its own, wider ceiling.
func TestHoneypotGroupNames(t *testing.T) {
	seen := map[string]string{}
	for _, g := range HoneypotPresetGroups {
		name := g.Name()
		if name == "" || strings.Contains(name, "(") || utf8.RuneCountInString(name) > 32 {
			t.Errorf("%s: name %q", g.ID, name)
		}
		if !strings.HasPrefix(g.Label, name) {
			t.Errorf("%s: name %q is not how the label %q starts", g.ID, name, g.Label)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("%s and %s share the name %q", prev, g.ID, name)
		}
		seen[name] = g.ID
	}
	if got := (HoneypotGroup{Label: "SQL injection signatures (sqlmap / probes)"}).Name(); got != "SQL injection signatures" {
		t.Errorf("Name() = %q", got)
	}
	if got := (HoneypotGroup{Label: "(all parenthesised)"}).Name(); got != "(all parenthesised)" {
		t.Errorf("a label that is only its parenthesis keeps it: %q", got)
	}
}
