package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The custom_rule row's breakdown by rule: the aggregate path reads the
// same rows as the scan, busiest rule first; a load that named no rule (an
// older challenge page) is in the card's custom_rule count and in no rule's.
func TestCaptchaForceRules_AggMatchesScan(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "cfrtest-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	seed := []struct{ ip, payload string }{
		{"1.1.1.1", `{"force_reason":"custom_rule","force_rule":"cr1"}`},
		{"2.2.2.2", `{"force_reason":"custom_rule","force_rule":"cr1"}`},
		{"2.2.2.2", `{"force_reason":"custom_rule","force_rule":"cr1"}`}, // the same address again
		{"3.3.3.3", `{"force_reason":"custom_rule","force_rule":"cr2"}`},
		{"4.4.4.4", `{"force_reason":"custom_rule"}`},                 // an older page: no rule
		{"5.5.5.5", `{"force_reason":"honeypot","force_rule":"cr1"}`}, // not a rule's challenge
	}
	for i, s := range seed {
		if _, err := d.Exec(
			`INSERT INTO unmask_event
				(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
				 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			 VALUES ('','','','','`+s.ip+`','UA','','',0,'load',0,0,'','',?,datetime('now','-30 minutes'))`,
			s.payload); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}
	ctx := context.Background()
	scan, err := captchaForceRulesScan(ctx, d, "", nil, 36)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	defer hourlyReady.Store(false)
	agg, err := captchaForceRulesAgg(ctx, d, 36)
	if err != nil {
		t.Fatalf("agg: %v", err)
	}
	want := []CaptchaForceRuleRow{{Rule: "cr1", Count: 3, UniqIP: 2}, {Rule: "cr2", Count: 1, UniqIP: 1}}
	for name, got := range map[string][]CaptchaForceRuleRow{"scan": scan, "agg": agg} {
		if len(got) != len(want) {
			t.Fatalf("%s: rows %+v, want %+v", name, got, want)
		}
		for i := range want {
			if got[i].Rule != want[i].Rule || got[i].Count != want[i].Count {
				t.Errorf("%s[%d]: %+v, want %+v", name, i, got[i], want[i])
			}
			if diff := got[i].UniqIP - want[i].UniqIP; diff > 1 || diff < -1 {
				t.Errorf("%s[%d]: uniq %d, want about %d", name, i, got[i].UniqIP, want[i].UniqIP)
			}
		}
	}
	// The card's custom_rule row counts the load that named no rule too.
	kinds, err := captchaForceBreakdownScan(ctx, d, "", nil, 36)
	if err != nil {
		t.Fatalf("breakdown: %v", err)
	}
	for _, k := range kinds {
		if k.Kind == "custom_rule" && k.Count != 5 {
			t.Errorf("custom_rule count %d, want 5", k.Count)
		}
	}
}
