package nginxconf

import (
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The noalpn_spoof group flags TLS fingerprints that carry a browser UA but send
// no ALPN.  Its whole safety argument is that it matches ONLY the no-ALPN form
// and never a genuine browser -- so pin both directions here.
func TestNoALPNSpoofPresetMatching(t *testing.T) {
	var grp *JA4VerdictGroup
	for i := range JA4VerdictGroups {
		if JA4VerdictGroups[i].ID == "noalpn_spoof" {
			grp = &JA4VerdictGroups[i]
			break
		}
	}
	if grp == nil {
		t.Fatal("noalpn_spoof group missing")
	}

	// Every rule is a bot verdict (no suspect / ok crept in) and its pattern
	// compiles anchored the way render emits it (~^...).
	for _, r := range grp.Rules {
		if r.Action != JA4ActionBot {
			t.Errorf("rule %d (%s): action %q, want bot", r.ID, r.Verdict, r.Action)
		}
		if _, err := regexp.Compile("^" + r.Pattern); err != nil {
			t.Errorf("rule %d pattern %q does not compile: %v", r.ID, r.Pattern, err)
		}
	}

	// A representative no-ALPN observation must match; the h2 form of the SAME
	// cipher and a genuine Chrome must NOT (that is the human-safety line).
	mustMatch := func(pat, ja4 string, want bool) {
		got := regexp.MustCompile("^" + pat).MatchString(ja4)
		if got != want {
			t.Errorf("pattern %q vs %q = %v, want %v", pat, ja4, got, want)
		}
	}
	// 6d1bcf7a4624 appears in the logs as both a no-ALPN (bot) and an h2 form.
	mustMatch("t13d[0-9]+00_6d1bcf7a4624_", "t13d260900_6d1bcf7a4624_188c7f576dcd", true)  // no-ALPN -> flagged
	mustMatch("t13d[0-9]+00_6d1bcf7a4624_", "t13d2610h2_6d1bcf7a4624_188c7f576dcd", false) // h2 -> left alone
	// Genuine Chrome (h2, real cipher) must never be caught by any rule here.
	chrome := "t13d1516h2_8daaf6152771_806a8c22fdea"
	for _, r := range grp.Rules {
		if regexp.MustCompile("^" + r.Pattern).MatchString(chrome) {
			t.Errorf("rule %d (%s) matches genuine Chrome %q -- would catch humans", r.ID, r.Verdict, chrome)
		}
	}
	// TLS1.2 no-ALPN rule matches its form but not the TLS1.2 h2 form.
	mustMatch("t12d[0-9]+00_8256d93fd366_", "t12d110500_8256d93fd366_deadbeef0000", true)
	mustMatch("t12d[0-9]+00_8256d93fd366_", "t12d1106h2_8256d93fd366_deadbeef0000", false)
}

// The group is AddedIn v0.1.25, so PresetIsNew must hide it from installs that
// have only seen 0.1.24 (no surprise CAPTCHA on upgrade) and render it once the
// operator's config reaches 0.1.25.
func TestNoALPNSpoofRenderGate(t *testing.T) {
	old := renderHTTPInc(t, func(s *settings.Settings) { s.Nginx.SeenVersion = "v0.1.24" })
	if strings.Contains(old, "6d1bcf7a4624") {
		t.Error("noalpn_spoof must stay gated for a pre-0.1.25 (seen 0.1.24) install")
	}
	now := renderHTTPInc(t, func(s *settings.Settings) { s.Nginx.SeenVersion = "v0.1.25" })
	for _, cipher := range []string{"6d1bcf7a4624", "b2d131b8446a", "4b1b1e8ff355", "c903b3b6e441"} {
		if !strings.Contains(now, cipher) {
			t.Errorf("0.1.25 http.inc is missing noalpn_spoof cipher %s", cipher)
		}
	}
}

// Built-in JA4 rule IDs are the immutable DB key; a duplicate would make two
// rules indistinguishable in the ja4_verdict_id column.
func TestJA4BuiltinRuleIDsUnique(t *testing.T) {
	seen := map[int]string{}
	for _, g := range JA4VerdictGroups {
		for _, r := range g.Rules {
			if prev, dup := seen[r.ID]; dup {
				t.Errorf("duplicate built-in JA4 rule ID %d: %q and %q", r.ID, prev, r.Verdict)
			}
			seen[r.ID] = r.Verdict
		}
	}
}
