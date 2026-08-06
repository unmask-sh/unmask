package nginxconf

import (
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A UA the operator put on a chain that ends in a CAPTCHA must not be let
// through by a proof-of-work cookie, and the gate has to reach the decision
// map for that to be true.
func TestCaptchaGradeGateRender(t *testing.T) {
	render := func(s settings.Settings) string {
		dir := t.TempDir()
		s.Nginx.OutputDir = dir
		if err := Render(s, dir, "test"); err != nil {
			t.Fatalf("render: %v", err)
		}
		b, err := os.ReadFile(dir + "/http.inc")
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// Disabling every preset group is how a test says "only my row counts":
	// the built-in target presets (curl / python-requests / headless) are on
	// by default and carry the default chain, so on an ordinary install they
	// arm this gate too -- which is the intended effect, not an accident.
	noPresets := func(s *settings.Settings) {
		for _, g := range ChallengeTargetGroups {
			s.Nginx.ChallengeTargets.DisabledPresets = append(s.Nginx.ChallengeTargets.DisabledPresets, g.ID)
		}
	}

	t.Run("a listed UA with the default chain arms the gate", func(t *testing.T) {
		var s settings.Settings
		noPresets(&s)
		// No action anywhere: the row inherits the install default, which is
		// pow_then_captcha -- so plain "list this UA" means CAPTCHA.
		s.Nginx.ChallengeTargets.Extra = []string{"contains:Bytespider"}
		out := render(s)
		if !strings.Contains(out, "$unmask_ua_needs_captcha") {
			t.Fatal("the UA map was not emitted")
		}
		if !strings.Contains(out, `"1:captcha" 1`) {
			t.Error("the grade map must admit a genuine CAPTCHA pass")
		}
		if !strings.Contains(out, "$bv_pass_ok:$is_search_bot") {
			t.Fatal("the decision map still keys on the ungraded pass -- the gate is inert")
		}
		// The rate-limit key map legitimately keeps asking "holds any pass",
		// so match the decision map's full key rather than a prefix.
		if strings.Contains(out, "$bv_any_valid:$is_search_bot:$is_bypass_ip:$is_bypass_path:$is_net_challenge") {
			t.Error("both gates cannot be wired at once")
		}
	})

	// The gate must not make the plugin verify the cookie twice: its variables
	// are non-cacheable, so every additional one that touches the cookie pays
	// the HMAC again -- on every request, which is how this project has twice
	// shipped a 13x regression.
	t.Run("the gate reads the kind the decision map already builds", func(t *testing.T) {
		var s settings.Settings
		noPresets(&s)
		s.Nginx.ChallengeTargets.Extra = []string{"contains:Bytespider"}
		out := render(s)
		gate := out[strings.Index(out, "map \"$unmask_ua_needs_captcha:"):]
		gate = gate[:strings.Index(gate, "}")]
		if strings.Contains(gate, "$bv_captcha_valid") || strings.Contains(gate, "$unmask_bv_kind") {
			t.Errorf("the gate key must reuse $bv_kind, got: %s", gate)
		}
	})
}

// The built-in challenge-target presets carry the default chain, so an
// ordinary install arms this gate without the operator writing a rule.  That
// is deliberate: those presets are curl / python-requests / headless, which
// have no legitimate way to hold a proof-of-work cookie except by minting one
// themselves -- the exact behaviour measured on the install that prompted
// this.  Pinned as a test because it is the widest-reaching consequence of the
// change, and it should never move by accident.
func TestCaptchaGradeGateArmsOnDefaultPresets(t *testing.T) {
	dir := t.TempDir()
	var s settings.Settings
	s.Nginx.OutputDir = dir
	if err := Render(s, dir, "test"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dir + "/http.inc")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "$unmask_ua_needs_captcha") {
		t.Fatal("a default install must arm the grade gate from its target presets")
	}
}

// The predicate itself, away from the render: which resolved action puts a UA
// behind a CAPTCHA requirement.  Tested directly because at render time the
// preset groups and the upstream rescue categories contribute their own
// patterns on the default chain, which is correct but would drown out what
// these cases are about.
func TestCaptchaGradeUAPatternsPredicate(t *testing.T) {
	base := func(action string) settings.Settings {
		var s settings.Settings
		for _, g := range ChallengeTargetGroups {
			s.Nginx.ChallengeTargets.DisabledPresets = append(s.Nginx.ChallengeTargets.DisabledPresets, g.ID)
		}
		s.Nginx.ChallengeTargets.Extra = []string{"contains:SomeBot"}
		s.Nginx.ChallengeTargets.ExtraAction = []string{action}
		return s
	}
	cases := []struct {
		action string
		want   bool
		why    string
	}{
		{"", true, "a blank action inherits the install default chain, which ends in a CAPTCHA"},
		{settings.RateChallengeCaptchaOnly, true, "the rule says CAPTCHA outright"},
		{settings.RateChallengePoWThenCaptcha, true, "the chain ends in a CAPTCHA"},
		{settings.RateChallengePoWOnly, false, "a proof-of-work rule is satisfied by a proof-of-work cookie"},
		{settings.RateChallengeDeny, false, "deny is enforced ahead of the cookie; it is not a grade question"},
	}
	for _, c := range cases {
		got := len(captchaGradeUAPatterns(base(c.action), "", nil)) > 0
		if got != c.want {
			t.Errorf("action %q -> armed=%v, want %v (%s)", c.action, got, c.want, c.why)
		}
	}
}
