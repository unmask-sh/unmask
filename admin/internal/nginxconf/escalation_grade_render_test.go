package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Each escalation tier keys its "would pass" field on the pass its own
// screen mints: a CAPTCHA-grade cookie when the tier's action ends in a
// CAPTCHA (the defaults), any pass when the operator set the tier to
// pow_only.  A proof-of-work cookie used to satisfy all three, so the
// CAPTCHA they escalate to was never reached by a client that solved -- or
// minted -- the proof-of-work.
func TestEscalationTiersDemandTheirGrade(t *testing.T) {
	all := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.StaleBrowserChallenge = true
		s.Global.HeaderIntegrity = true
	})
	for _, want := range []string{
		`:$unmask_stale_browser:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_captcha_valid" $fc_after_stale {`,
		`:$unmask_header_mismatch:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_captcha_valid" $fc_after_header {`,
		`:$unmask_ua_tls_mismatch:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_captcha_valid" $final_challenge {`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("default actions: missing %q", want)
		}
	}
	pow := renderHTTPInc(t, func(s *settings.Settings) {
		s.Global.StaleBrowserChallenge = true
		s.Global.StaleBrowserAction = settings.RateChallengePoWOnly
		s.Global.HeaderIntegrity = true
		s.Global.HeaderIntegrityAction = settings.RateChallengePoWOnly
		s.Global.UATLSConsistencyAction = settings.RateChallengePoWOnly
	})
	for _, want := range []string{
		`:$unmask_stale_browser:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_any_valid" $fc_after_stale {`,
		`:$unmask_header_mismatch:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_any_valid" $fc_after_header {`,
		`:$unmask_ua_tls_mismatch:$is_search_bot:$is_bypass_ip:$is_bypass_path:$bv_any_valid" $final_challenge {`,
	} {
		if !strings.Contains(pow, want) {
			t.Errorf("pow_only actions: missing %q", want)
		}
	}
	if strings.Contains(pow, `$bv_captcha_valid" $f`) {
		t.Error("pow_only actions: a tier still demands the CAPTCHA grade")
	}
}
