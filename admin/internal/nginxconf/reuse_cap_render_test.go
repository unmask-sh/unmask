package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The pass-cookie reuse cap renders as one zone whose key is the client
// address for a request WITH a valid _bv only -- the reverse of every other
// rate key -- applied in protect.inc with the configured burst.  It is on by
// default (an untouched config renders it at the seeds); switched off, or held
// by the upgrade review, nothing of it renders.
func TestReuseCapRender(t *testing.T) {
	httpInc, protectInc := renderBothIncs(t, func(s *settings.Settings) {
		s.RateLimit.Reuse = settings.ReuseLimitConfig{} // untouched: on, at the seeds
	})
	for _, want := range []string{
		// Every pass but a solved CAPTCHA is counted: that CAPTCHA is the
		// cap's way out for a person behind a busy address.
		`map $unmask_bv_kind $bv_reuse_counted { default 1;  ""  0;  "captcha" 0; }`,
		`map "$bv_reuse_counted:$is_search_bot:$is_bypass_ip:$is_bypass_path" $rate_limit_key_reuse {`,
		`"~^1:"        $unmask_client_net;`,
		// The seed, 10,000 a day, is 6.9 a minute: nginx counts whole
		// requests a minute.
		`limit_req_zone $rate_limit_key_reuse zone=unmask_reuse:10m rate=7r/m;`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	// The trusted sources stay exempt, ahead of the cookie match.
	block := httpInc[strings.Index(httpInc, "$rate_limit_key_reuse {"):]
	block = block[:strings.Index(block, "}")]
	if strings.Index(block, `"~^.:1:"`) > strings.Index(block, `"~^1:"`) {
		t.Error("the search-bot exemption must come before the cookie match (first regex wins)")
	}
	if !strings.Contains(protectInc, "limit_req zone=unmask_reuse burst=2000 nodelay;") {
		t.Error("protect.inc does not apply the reuse zone")
	}

	httpOff, protectOff := renderBothIncs(t, func(s *settings.Settings) {
		s.RateLimit.Reuse = settings.ReuseLimitConfig{Disabled: true, PerDay: 20000, Burst: 3000} // tuned, off
	})
	if strings.Contains(httpOff, "unmask_reuse") || strings.Contains(protectOff, "unmask_reuse") ||
		strings.Contains(httpOff, "$bv_reuse_counted") {
		t.Error("a switched-off cap must render nothing")
	}

	// An install on the "review" upgrade policy that has not acknowledged the
	// release that turned the cap on keeps it inert, and lists it as held.
	httpHeld, _ := renderBothIncs(t, func(s *settings.Settings) {
		s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
		s.Nginx.EnforcementReviewedVersion = "v0.1.48"
	})
	if strings.Contains(httpHeld, "unmask_reuse") {
		t.Error("a cap held by the upgrade review must render nothing")
	}
	var held settings.Settings
	held.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
	held.Nginx.EnforcementReviewedVersion = "v0.1.48"
	if ReuseCapActive(held) {
		t.Error("ReuseCapActive must be false while the upgrade review holds it")
	}
	found := false
	for _, hp := range HeldEnforcementPresets(held) {
		found = found || hp.ID == "reuse_cap"
	}
	if !found {
		t.Error("the held cap must be listed for the upgrade review")
	}
	held.Nginx.EnforcementReviewedVersion = settings.ReuseAddedIn
	if !ReuseCapActive(held) {
		t.Error("acknowledging the release that added the cap must put it in force")
	}
}
