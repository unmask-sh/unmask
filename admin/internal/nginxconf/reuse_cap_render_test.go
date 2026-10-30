package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The pass-cookie reuse cap renders as zones whose keys are set for a request
// WITH a valid _bv only -- the reverse of every other rate key: the client
// address (and the solved CAPTCHA's five-fold twin), and the pass itself, by
// the identity the plugin names in $unmask_bv_id -- applied in protect.inc
// with the configured bursts.  It is on by default (an untouched config
// renders it at the seeds); switched off, or held by the upgrade review,
// nothing of it renders; with the cap acknowledged but not the release that
// added the per-pass tier, the address zones render alone.
func TestReuseCapRender(t *testing.T) {
	httpInc, protectInc := renderBothIncs(t, func(s *settings.Settings) {
		s.RateLimit.Reuse = settings.ReuseLimitConfig{} // untouched: on, at the seeds
	})
	for _, want := range []string{
		// Every pass but a solved CAPTCHA is counted: that CAPTCHA is the
		// cap's way out for a person behind a busy address.
		`map $unmask_bv_kind $bv_reuse_counted { default 1;  ""  0;  "captcha" 0; }`,
		`map "$bv_reuse_counted:$is_bypass_ip:$is_bypass_path" $rate_limit_key_reuse {`,
		`"~^1:"      $unmask_client_net;`,
		// The seed, 10,000 a day, is 6.9 a minute: nginx counts whole
		// requests a minute.
		`limit_req_zone $rate_limit_key_reuse zone=unmask_reuse:10m rate=7r/m;`,
		// One pass at a time: the plugin's identity for the pass that
		// verified is the key, 16 hex digits, "" (no key) otherwise.  The
		// seed, 500 an hour, is 8.3 a minute.
		`map "$unmask_bv_id:$is_bypass_ip:$is_bypass_path" $rate_limit_key_pass {`,
		`"~^(?<bv_pass_v>[0-9a-f]{16}):"  $bv_pass_v;`,
		`limit_req_zone $rate_limit_key_pass zone=unmask_reuse_pass:10m rate=9r/m;`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	passBlock := httpInc[strings.Index(httpInc, "$rate_limit_key_pass {"):]
	passBlock = passBlock[:strings.Index(passBlock, "}")]
	if strings.Index(passBlock, `"~^[^:]*:1:"`) > strings.Index(passBlock, `(?<bv_pass_v>`) {
		t.Error("the per-pass map must exempt the trusted sources before the identity match")
	}
	if !strings.Contains(protectInc, "limit_req zone=unmask_reuse_pass burst=500 nodelay;") {
		t.Error("protect.inc does not apply the per-pass zone with the hourly figure as its burst")
	}
	// Tuned: the hourly figure is the burst and, rounded up, the rate.
	httpTuned, protectTuned := renderBothIncs(t, func(s *settings.Settings) {
		s.RateLimit.Reuse = settings.ReuseLimitConfig{PassPerHour: 1210}
	})
	if !strings.Contains(httpTuned, "zone=unmask_reuse_pass:10m rate=21r/m;") ||
		!strings.Contains(protectTuned, "limit_req zone=unmask_reuse_pass burst=1210 nodelay;") {
		t.Error("a tuned per-pass figure must set the zone's rate (rounded up) and the burst")
	}
	// The trusted sources stay exempt, ahead of the cookie match.
	block := httpInc[strings.Index(httpInc, "$rate_limit_key_reuse {"):]
	block = block[:strings.Index(block, "}")]
	if strings.Index(block, `"~^.:1:"`) > strings.Index(block, `"~^1:"`) {
		t.Error("the bypass exemptions must come before the cookie match (first regex wins)")
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

	// The cap acknowledged, the release that added the per-pass tier not:
	// the address zones render, the per-pass one does not, and the review
	// lists the tier (and not the cap, which is in force).
	httpTier, protectTier := renderBothIncs(t, func(s *settings.Settings) {
		s.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
		s.Nginx.EnforcementReviewedVersion = settings.ReuseAddedIn
	})
	if !strings.Contains(httpTier, "zone=unmask_reuse:10m") || !strings.Contains(httpTier, "zone=unmask_reuse_captcha:10m") {
		t.Error("with the cap acknowledged the address zones must render")
	}
	if strings.Contains(httpTier, "unmask_reuse_pass") || strings.Contains(httpTier, "$unmask_bv_id") ||
		strings.Contains(protectTier, "unmask_reuse_pass") {
		t.Error("the per-pass tier must render nothing while the review holds it")
	}
	if ReusePassActive(held) {
		t.Error("ReusePassActive must be false while the upgrade review holds the tier")
	}
	ids := map[string]bool{}
	for _, hp := range HeldEnforcementPresets(held) {
		ids[hp.ID] = true
	}
	if !ids["reuse_pass"] || ids["reuse_cap"] {
		t.Errorf("the review must list the held tier and not the acknowledged cap, got %v", ids)
	}
	held.Nginx.EnforcementReviewedVersion = settings.ReusePassAddedIn
	if !ReusePassActive(held) {
		t.Error("acknowledging the release that added the tier must put it in force")
	}
	// Switched off, the tier is not listed either: there is nothing to hold.
	off := held
	off.Nginx.EnforcementReviewedVersion = settings.ReuseAddedIn
	off.RateLimit.Reuse.Disabled = true
	for _, hp := range HeldEnforcementPresets(off) {
		if hp.ID == "reuse_pass" || hp.ID == "reuse_cap" {
			t.Errorf("a switched-off cap must not be listed as held (%s)", hp.ID)
		}
	}
}
