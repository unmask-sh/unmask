package nginxconf

import (
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// cbSettings: an install subscribing to the community feed with the given
// action ("" = the operator has not picked one).
func cbSettings(mode, action string) settings.Settings {
	var s settings.Settings
	s.CommunityBans.SubscribeMode = mode
	s.CommunityBans.Action = action
	return s
}

// The rendered conf must agree with the resolver for every action: a hit
// challenges (and grades) or denies, never both and never neither.  A missing
// wire here is invisible in the UI -- the action reads correctly on the
// settings page while nginx enforces something else.
func TestCommunityBansRenderMatchesTheResolvedAction(t *testing.T) {
	for _, c := range []struct {
		action        string
		wantDeny      bool
		wantGrade     bool
		wantChallenge bool
	}{
		{"", false, true, true},
		{settings.RateChallengePoWOnly, false, false, true},
		{settings.RateChallengeCaptchaOnly, false, true, true},
		{settings.RateChallengePoWThenCaptcha, false, true, true},
		{settings.RateChallengeDeny, true, false, false},
	} {
		name := c.action
		if name == "" {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			s := cbSettings(settings.SubscribeFetchApply, c.action)
			inc := renderHTTPInc(t, func(d *settings.Settings) { *d = s })

			gotDeny := strings.Contains(inc, "map $community_bans_hit $unmask_cb_deny {")
			gotGrade := strings.Contains(inc, "map $community_bans_hit $unmask_cb_captcha {")
			gotChallenge := strings.Contains(inc, "map $community_bans_hit $unmask_cb_challenge {")
			if gotDeny != c.wantDeny {
				t.Errorf("deny wiring=%v, want %v", gotDeny, c.wantDeny)
			}
			if gotGrade != c.wantGrade {
				t.Errorf("captcha-grade wiring=%v, want %v", gotGrade, c.wantGrade)
			}
			if gotChallenge != c.wantChallenge {
				t.Errorf("challenge wiring=%v, want %v", gotChallenge, c.wantChallenge)
			}
			// Whatever the action, both variables must be DEFINED: nginx
			// aborts on an undefined variable, and the keys carrying them are
			// emitted unconditionally.  (Under deny they are defined as
			// constants; under a challenge action they follow the hit.)
			for _, v := range []string{`\$unmask_cb_challenge`, `\$unmask_cb_captcha`} {
				if !regexp.MustCompile(`(?m)^map \S+ ` + v + `\s+\{`).MatchString(inc) {
					t.Errorf("%s is never defined", strings.TrimPrefix(v, `\`))
				}
			}
			// A denying feed must bring the deny plumbing with it.
			if c.wantDeny && !strings.Contains(inc, "$unmask_axis_deny {") {
				t.Error("action=deny renders no deny dispatch")
			}
		})
	}
}

// Every configuration must leave the feed variables either defined or unused.
// The repo-wide undefined-variable guard reads the TEMPLATE, so a variable
// defined only inside one {{if}} branch but used unconditionally passes it and
// takes nginx down at startup instead.  This walks the rendered output for the
// configurations that turn the feed off, which is what most installs run.
func TestCommunityBansVariablesAreConsistentWhenNotSubscribing(t *testing.T) {
	for _, mode := range []string{"", settings.SubscribeOff, settings.SubscribeFetch} {
		name := mode
		if name == "" {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			s := cbSettings(mode, "")
			inc := renderHTTPInc(t, func(d *settings.Settings) { *d = s })
			for _, v := range []string{"community_bans_hit", "unmask_cb_challenge", "unmask_cb_captcha", "unmask_cb_deny"} {
				used := regexp.MustCompile(`\$` + v + `\b`).MatchString(inc)
				defined := regexp.MustCompile(`(?m)^map \S+ \$` + v + `\s+\{`).MatchString(inc)
				if used && !defined {
					t.Errorf("$%s is used but never defined -- nginx would refuse to start", v)
				}
			}
		})
	}
}

// The feed must not be able to override a rescue.  Native encodes this by
// ordering the exemptions above the feed slot in $final_challenge; this pins
// that ordering so a later edit cannot quietly let a shared-list entry take
// out a search bot or an operator-trusted IP.
func TestCommunityBansCannotOverrideARescue(t *testing.T) {
	s := cbSettings(settings.SubscribeFetchApply, settings.RateChallengeCaptchaOnly)
	inc := renderHTTPInc(t, func(d *settings.Settings) { *d = s })

	key := "$is_bypass_path:$unmask_cb_challenge:"
	if !strings.Contains(inc, key) {
		t.Fatalf("the feed slot is not where the rescues can still win: %q missing", key)
	}
	for _, exempt := range []string{
		`"~^0:1:"                          0;`, // search bot
		`"~^0:0:1:"                        0;`, // bypass IP
		`"~^0:0:0:1:"                      0;`, // bypass path
	} {
		if !strings.Contains(inc, exempt) {
			t.Errorf("rescue row missing from the decision map: %s", exempt)
		}
	}
	if !strings.Contains(inc, `"~^0:0:0:0:1:"                    1;`) {
		t.Error("the feed slot does not challenge")
	}
}

// ServeChallenge and the nginx render must agree on the protected-path axis
// too: the feed used to reach the visitor disguised as protected_mode, which
// is why a hit arrived with no reason and an unrelated chain.
func TestCommunityBansNoLongerMasqueradesAsProtected(t *testing.T) {
	s := cbSettings(settings.SubscribeFetchApply, settings.RateChallengeCaptchaOnly)
	inc := renderHTTPInc(t, func(d *settings.Settings) { *d = s })
	if strings.Contains(inc, "$protected_mode_eff") {
		t.Error("the protected_mode_eff shim is back: a feed hit is impersonating a protected path again")
	}
	// And the protected axis still resolves independently.
	if ChModeForProtectedMode(ProtectedModePoW) != settings.RateChallengePoWOnly {
		t.Error("protected mode resolution changed")
	}
}
