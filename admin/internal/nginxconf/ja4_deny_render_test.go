package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The JA4 tab offers "deny" for its default, its presets and its rows, but the
// rendered deny decision keyed only on geo / ASN / UA -- so picking it produced
// a challenge, never a 403, and the option was dead on this wire.  A verdict
// that resolves to deny now feeds $unmask_ja4_deny and $unmask_axis_deny.
// Rescues stay above it: the deny is routed through $unmask_deny_unrescued, so
// a search bot or a bypassed address is never denied by a fingerprint.
func TestJA4DenyRendersIntoTheDenyDecision(t *testing.T) {
	// Nothing configured: no map, and the deny key carries a literal 0 so the
	// install pays nothing for an axis it does not use.
	off := renderHTTPInc(t, nil)
	if strings.Contains(off, "$unmask_ja4_deny {") {
		t.Error("no JA4 deny configured, yet the map was rendered")
	}

	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.JA4Verdicts.DefaultAction = settings.RateChallengeDeny
	})
	for _, want := range []string{
		"map $effective_ja4 $unmask_ja4_deny {",
		`$unmask_ua_deny:$unmask_ja4_deny" $unmask_axis_deny {`,
		`"~^0:0:0:1$" 1;`,                          // the JA4 slot denies
		"map $unmask_axis_deny $unmask_deny_raw {", // still routed through the rescue gate
	} {
		if !strings.Contains(on, want) {
			t.Errorf("with a JA4 deny configured, http.inc is missing %q", want)
		}
	}
	// A bot verdict actually made it into the map (the presets ship several).
	i := strings.Index(on, "$unmask_ja4_deny {")
	if i < 0 || !strings.Contains(on[i:i+2000], `" 1;`) {
		t.Error("the JA4 deny map has no patterns in it")
	}
}
