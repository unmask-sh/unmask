package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestCaptchaPassFailForceReasonCounts locks the phase filters that keep the
// pass-by-axis and fail-by-axis breakdowns from bleeding into each other:
// the pass side counts only the two solved-CAPTCHA phases
// (captchaPassPhases), the fail side only verify_ng, and a load-phase event
// (which is neither a pass nor a fail) must land in neither.  Both group by
// $.force_reason.  If a phase list drifts, the two cards would double-count or
// silently drop an axis; this guards exactly that.
func TestCaptchaPassFailForceReasonCounts(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "cpffr-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	seed := []struct {
		ip      string
		phase   string
		payload string
	}{
		// pass side (solved CAPTCHA) -- both solve phases count
		{"1.1.1.1", "bv_captcha_only", `{"force_reason":"header"}`},
		{"2.2.2.2", "bv_pow_then_captcha", `{"force_reason":"asn"}`},
		{"3.3.3.3", "bv_captcha_only", `{"force_reason":"none"}`},
		// fail side (verify_ng) -- header once, none twice
		{"4.4.4.4", "verify_ng", `{"force_reason":"header"}`},
		{"5.5.5.5", "verify_ng", `{"force_reason":"none"}`},
		{"6.6.6.6", "verify_ng", `{"force_reason":"none"}`},
		// neither pass nor fail: a load-phase geo escalation must not appear
		// in either breakdown (guards the phase filter, not the reason).
		{"7.7.7.7", "load", `{"force_reason":"geo"}`},
	}
	for i, s := range seed {
		if _, err := d.Exec(
			`INSERT INTO unmask_event
				(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
				 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			 VALUES ('','','','','`+s.ip+`','UA','','',0,?,0,0,'','',?,datetime('now','-30 minutes'))`,
			s.phase, s.payload); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}

	ctx := context.Background()

	pass, err := CaptchaPassForceReasonCounts(ctx, d, "", nil, 36)
	if err != nil {
		t.Fatalf("pass: %v", err)
	}
	wantPass := map[string]int{"header": 1, "asn": 1, "none": 1}
	if len(pass) != len(wantPass) {
		t.Errorf("pass kinds = %v, want %v", pass, wantPass)
	}
	for k, n := range wantPass {
		if pass[k] != n {
			t.Errorf("pass[%s] = %d, want %d", k, pass[k], n)
		}
	}
	if _, leaked := pass["geo"]; leaked {
		t.Errorf("pass leaked load-phase geo: %v", pass)
	}

	fail, err := CaptchaFailForceReasonCounts(ctx, d, "", nil, 36)
	if err != nil {
		t.Fatalf("fail: %v", err)
	}
	wantFail := map[string]int{"header": 1, "none": 2}
	if len(fail) != len(wantFail) {
		t.Errorf("fail kinds = %v, want %v", fail, wantFail)
	}
	for k, n := range wantFail {
		if fail[k] != n {
			t.Errorf("fail[%s] = %d, want %d", k, fail[k], n)
		}
	}
	if _, leaked := fail["geo"]; leaked {
		t.Errorf("fail leaked load-phase geo: %v", fail)
	}
	// cross-check: the pass phases must not appear on the fail side.
	if _, leaked := fail["asn"]; leaked {
		t.Errorf("fail leaked a pass-phase reason (asn): %v", fail)
	}
}
