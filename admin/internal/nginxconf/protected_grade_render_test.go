package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestProtectedGradeRender pins the native-wire CAPTCHA-grade enforcement on the
// protected-path axis.  Regression: a captcha-graded protected path (the
// /unmask/admin gate) was satisfied by a PoW-only cookie because the pass gate's
// grade requirement keyed only on the UA axis ($unmask_ua_needs_captcha), never
// on $protected_mode.  A headless PoW-solver could therefore reach the gated
// path with a cookie it minted itself.  The fix folds the protected axis into
// $unmask_needs_captcha_grade and makes the pass gate read $bv_pass_ok.
func TestProtectedGradeRender(t *testing.T) {
	// The flag that forces the grade maps on for the protected axis, isolated
	// from the challenge-target UA patterns (which are non-empty by default).
	for _, tc := range []struct {
		name string
		mode string
		want bool
	}{
		{"pow imposes no grade", ProtectedModePoW, false},
		{"captcha needs grade", ProtectedModeCaptcha, true},
		{"pow_then_captcha needs grade", ProtectedModePoWThenCaptcha, true},
	} {
		var s settings.Settings
		s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{{Path: `^/x/`, Mode: tc.mode}}
		d, err := buildRenderData(s, t.TempDir(), "t")
		if err != nil {
			t.Fatalf("%s: buildRenderData: %v", tc.name, err)
		}
		if d.ProtectedNeedsCaptchaGrade != tc.want {
			t.Errorf("%s: ProtectedNeedsCaptchaGrade=%v, want %v", tc.name, d.ProtectedNeedsCaptchaGrade, tc.want)
		}
	}

	// A community-bans subscription forces CAPTCHA on a hit -> it too must flip
	// the flag so a PoW cookie cannot satisfy a bans-forced captcha.
	var sb settings.Settings
	sb.CommunityBans.SubscribeMode = "fetch_apply"
	if d, err := buildRenderData(sb, t.TempDir(), "t"); err != nil {
		t.Fatal(err)
	} else if !d.ProtectedNeedsCaptchaGrade {
		t.Error("a community-bans subscription should require the CAPTCHA-grade maps")
	}

	// The rendered grade signal folds BOTH the UA axis and the protected axis,
	// the pass gate reads the grade-aware $bv_pass_ok, and every protected mode
	// (incl. the new pow_then_captcha, and no leftover "strict") is wired.
	inc := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{
			{Path: `^/vault/`, Mode: ProtectedModePoWThenCaptcha},
			{Path: `^/members/`, Mode: ProtectedModeCaptcha},
			{Path: `^/light/`, Mode: ProtectedModePoW},
		}
	})
	for _, want := range []string{
		`map "$unmask_ua_needs_captcha:$protected_mode_eff" $unmask_needs_captcha_grade`,
		`"0:captcha"`,          // protected captcha -> needs a CAPTCHA-grade cookie
		`"0:pow_then_captcha"`, // protected chain   -> needs a CAPTCHA-grade cookie
		`map "$unmask_needs_captcha_grade:$bv_kind" $bv_pass_ok`,
		`map "$bv_pass_ok:$is_search_bot:`,       // pass gate reads the grade-aware var
		`"pow_then_captcha" "pow_then_captcha";`, // $protected_mode map value
		`"~^0:0:0:0:0:pow_then_captcha:"`,        // final_challenge_base rows
		`"~^0:0:0:0:0:captcha:"`,
		`"~^0:0:0:0:0:pow:"`,
	} {
		if !strings.Contains(inc, want) {
			t.Errorf("expected %q in http.inc", want)
		}
	}
	if strings.Contains(inc, `"strict"`) {
		t.Error(`removed protected mode "strict" still present in http.inc`)
	}
}
