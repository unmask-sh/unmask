package nginxconf

import (
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The global posture -- the chain the Operating-mode bucket serves a request
// no other axis claimed -- was the one captcha-ending chain with no grade
// signal: on a site whose posture is pow_then_captcha a proof-of-work cookie
// counted as a pass, so a client that read the page and minted the cookie
// itself was never asked for the CAPTCHA the posture ends in.  The demand
// stands only where the posture decided the request: every other axis serves
// its own chain and brings its own grade signal, and demanding the posture's
// grade there would hand a visitor a screen whose pass is refused, forever.
const postureGateKey = "$unmatched_chain_action:$unmask_cb_challenge:$is_net_challenge:$protected_mode:$is_challenge_target:$ja4_hit_flag:$serve_bot_challenge"

// postureGateRows reads the rendered $unmask_global_captcha map: its key and
// its exact-match rows, so a test can evaluate it the way nginx does -- the
// key's fields joined by ":", looked up as one string, default 0.
func postureGateRows(t *testing.T, inc string) (key string, eval func(string) string) {
	t.Helper()
	i := strings.Index(inc, `map "$unmatched_chain_action:`)
	if i < 0 {
		t.Fatal("the $unmask_global_captcha map was not emitted")
	}
	body := inc[i:]
	body = body[:strings.Index(body, "\n}")]
	head := body[:strings.Index(body, "\n")]
	key = strings.TrimSuffix(strings.TrimPrefix(head, `map "`), `" $unmask_global_captcha {`)
	rows := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s*"([^"~]*)"\s+(\S+);`).FindAllStringSubmatch(body, -1) {
		rows[m[1]] = m[2]
	}
	return key, func(in string) string {
		if v, ok := rows[in]; ok {
			return v
		}
		return "0"
	}
}

// Silence the shipped challenge-target presets so the posture is the only UA
// source under test.
func postureNoPresets(s *settings.Settings) {
	for _, g := range ChallengeTargetGroups {
		s.Nginx.ChallengeTargets.DisabledPresets = append(s.Nginx.ChallengeTargets.DisabledPresets, g.ID)
	}
}

func TestGlobalPostureDemandsItsGrade(t *testing.T) {
	// Known browsers on pow_only, everything else on pow_then_captcha: the
	// split an operator uses to keep real browsers transparent while the
	// unknown bucket ends in a CAPTCHA.
	inc := renderHTTPInc(t, func(s *settings.Settings) {
		postureNoPresets(s)
		s.Global.KnownBrowserAction = settings.RateChallengePoWOnly
		s.Global.UnknownUAAction = settings.RateChallengePoWThenCaptcha
	})
	for _, want := range []string{
		`map "$unmask_ua_needs_captcha$unmask_cr_captcha$unmask_global_captcha" $unmask_ua_captcha_eff {`,
		`map "$unmask_needs_captcha_grade:$bv_kind" $bv_pass_ok`,
		`"1:captcha" 1`,
		`map "$bv_pass_ok:$is_search_bot:`, // the decision map reads the graded pass
		"    default \"pow_then_captcha\";\n    1       \"pow_only\";", // the bucket map the gate keys on
	} {
		if !strings.Contains(inc, want) {
			t.Errorf("missing %q", want)
		}
	}
	key, eval := postureGateRows(t, inc)
	if key != postureGateKey {
		t.Fatalf("gate key = %q, want %q", key, postureGateKey)
	}
	for _, c := range []struct {
		name, in, want string
	}{
		{"the unknown bucket ends in a CAPTCHA: demanded", "pow_then_captcha:0:0::0:0:0", "1"},
		{"a captcha_only bucket: demanded", "captcha_only:0:0::0:0:0", "1"},
		{"a known browser on pow_only is not swept in", "pow_only:0:0::0:0:0", "0"},
		{"a pass bucket demands nothing", "pass:0:0::0:0:0", "0"},
		{"a deny bucket is enforced elsewhere", "deny:0:0::0:0:0", "0"},
		// Each axis ranked above the posture decides the request and serves
		// its own chain; the posture stands down.
		{"community feed hit", "pow_then_captcha:1:0::0:0:0", "0"},
		{"country / network / custom rule", "pow_then_captcha:0:1::0:0:0", "0"},
		{"protected path, pow mode", "pow_then_captcha:0:0:pow:0:0:0", "0"},
		{"protected path, captcha mode", "pow_then_captcha:0:0:captcha:0:0:0", "0"},
		{"black-list UA", "pow_then_captcha:0:0::1:0:0", "0"},
		{"bot-verdict fingerprint", "pow_then_captcha:0:0::0:1:0", "0"},
		{"honeypot trip", "pow_then_captcha:0:0::0:0:1", "0"},
	} {
		if got := eval(c.in); got != c.want {
			t.Errorf("%s: %q -> %s, want %s", c.name, c.in, got, c.want)
		}
	}
}

// A posture that ends in no CAPTCHA demands nothing: the map is a constant
// (the gate stays armed by its other sources) and a proof-of-work cookie
// keeps passing the posture as before.
func TestGlobalPosturePoWOnlyDemandsNothing(t *testing.T) {
	inc := renderHTTPInc(t, func(s *settings.Settings) {
		postureNoPresets(s)
		s.Global.KnownBrowserAction = settings.RateChallengePoWOnly
		s.Global.UnknownUAAction = settings.RateChallengePoWOnly
		// Keep the grade block emitted through another source, so the
		// constant form is what is under test rather than the block's absence.
		s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{{Path: `^/vault/`, Mode: ProtectedModeCaptcha}}
	})
	if !strings.Contains(inc, `map "" $unmask_global_captcha { default 0; }`) {
		t.Error("a pow_only posture must render the constant 0 map")
	}
	if strings.Contains(inc, `map "$unmatched_chain_action:`) {
		t.Error("a pow_only posture must not key the gate on the posture")
	}
	if !strings.Contains(inc, `map "$unmask_ua_needs_captcha$unmask_cr_captcha$unmask_global_captcha" $unmask_ua_captcha_eff {`) {
		t.Error("the UA source must still fold the (constant) posture signal, so the key keeps one shape")
	}
}

// The render flag behind the block: either bucket ending in a CAPTCHA arms
// the grade gate on its own; the install default (pow_only both) does not.
func TestGlobalPostureGradeFlag(t *testing.T) {
	for _, tc := range []struct {
		name, known, unknown string
		want                 bool
	}{
		{"install default", "", "", false},
		{"pow_only both", settings.RateChallengePoWOnly, settings.RateChallengePoWOnly, false},
		{"pass both", "pass", "pass", false},
		{"known pow_then_captcha", settings.RateChallengePoWThenCaptcha, settings.RateChallengePoWOnly, true},
		{"unknown captcha_only", settings.RateChallengePoWOnly, settings.RateChallengeCaptchaOnly, true},
		{"unknown pow_then_captcha, known pass", "pass", settings.RateChallengePoWThenCaptcha, true},
		{"deny both", settings.RateChallengeDeny, settings.RateChallengeDeny, false},
	} {
		var s settings.Settings
		postureNoPresets(&s)
		s.Global.KnownBrowserAction = tc.known
		s.Global.UnknownUAAction = tc.unknown
		d, err := buildRenderData(s, t.TempDir(), "t")
		if err != nil {
			t.Fatalf("%s: buildRenderData: %v", tc.name, err)
		}
		if d.GlobalNeedsCaptchaGrade != tc.want {
			t.Errorf("%s: GlobalNeedsCaptchaGrade=%v, want %v", tc.name, d.GlobalNeedsCaptchaGrade, tc.want)
		}
		if tc.want && !d.GradeCheckedPass {
			t.Errorf("%s: the posture must arm the shared grade gate", tc.name)
		}
	}
}

// An escalation tier replaces the served chain with its own screen.  When
// that screen does not end in a CAPTCHA the tier's signal joins the key and
// the demand stands down for a request the tier fires on -- otherwise the
// visitor would solve the tier's proof of work and be refused for it.  A tier
// whose screen ends in a CAPTCHA (every tier's default) mints the grade
// demanded and adds no field.
func TestGlobalPostureStandsDownForAPoWTier(t *testing.T) {
	captcha := func(s *settings.Settings) {
		postureNoPresets(s)
		s.Global.KnownBrowserAction = settings.RateChallengePoWThenCaptcha
		s.Global.UnknownUAAction = settings.RateChallengePoWThenCaptcha
	}
	t.Run("default tiers add no field", func(t *testing.T) {
		inc := renderHTTPInc(t, func(s *settings.Settings) {
			captcha(s)
			s.Global.StaleBrowserChallenge = true
			s.Global.HeaderIntegrity = true
		})
		if key, _ := postureGateRows(t, inc); key != postureGateKey {
			t.Errorf("key = %q, want the bare key: every default tier screen ends in a CAPTCHA", key)
		}
	})
	t.Run("a pow_only stale tier joins the key", func(t *testing.T) {
		inc := renderHTTPInc(t, func(s *settings.Settings) {
			captcha(s)
			s.Global.StaleBrowserChallenge = true
			s.Global.StaleBrowserAction = settings.RateChallengePoWOnly
		})
		key, eval := postureGateRows(t, inc)
		if want := postureGateKey + ":$unmask_stale_browser"; key != want {
			t.Fatalf("key = %q, want %q", key, want)
		}
		if got := eval("pow_then_captcha:0:0::0:0:0:0"); got != "1" {
			t.Errorf("a fresh browser under the posture: %s, want 1", got)
		}
		if got := eval("pow_then_captcha:0:0::0:0:0:1"); got != "0" {
			t.Errorf("a stale browser the tier hands a proof of work: %s, want 0", got)
		}
	})
	t.Run("pow_only header and UA-TLS tiers join the key", func(t *testing.T) {
		inc := renderHTTPInc(t, func(s *settings.Settings) {
			captcha(s)
			s.Global.HeaderIntegrity = true
			s.Global.HeaderIntegrityAction = settings.RateChallengePoWOnly
			s.Global.UATLSConsistencyAction = settings.RateChallengePoWOnly
		})
		key, eval := postureGateRows(t, inc)
		if want := postureGateKey + ":$unmask_header_mismatch:$unmask_ua_tls_mismatch"; key != want {
			t.Fatalf("key = %q, want %q", key, want)
		}
		// The UA-TLS signal is empty when the two agree, a word when not.
		if got := eval("captcha_only:0:0::0:0:0:0:"); got != "1" {
			t.Errorf("no tier firing: %s, want 1", got)
		}
		if got := eval("captcha_only:0:0::0:0:0:1:"); got != "0" {
			t.Errorf("header tier firing: %s, want 0", got)
		}
		if got := eval("captcha_only:0:0::0:0:0:0:family"); got != "0" {
			t.Errorf("UA-TLS tier firing: %s, want 0", got)
		}
	})
}
