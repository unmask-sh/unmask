package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestForceReasonPerRow verifies the per-row escalation-axis surfacing added to
// the recent-passers list (CaptchaPassRecent, one value per event) and the
// verify_ng IP ranking (VerifyNGRanking, GROUP_CONCAT(DISTINCT) with "none"
// folded out).  It pins two things the SQL must get right and that differ
// across drivers: the DISTINCT concat runs on the pure-Go SQLite driver, and
// an IP whose failures are all "none" yields no badge (empty), not "none".
func TestForceReasonPerRow(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "frpr-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// ip packed as 4 bytes; use distinct low IPs so ipFromBytes is stable.
	seed := []struct {
		ipb   []byte
		phase string
		fr    string
	}{
		// verify_ng ranking:
		//   A(1.0.0.1): stale, stale, none  -> ["stale"]  (distinct + none out)
		{[]byte{1, 0, 0, 1}, "verify_ng", "stale"},
		{[]byte{1, 0, 0, 1}, "verify_ng", "stale"},
		{[]byte{1, 0, 0, 1}, "verify_ng", "none"},
		//   B(1.0.0.2): asn, none           -> ["asn"]
		{[]byte{1, 0, 0, 2}, "verify_ng", "asn"},
		{[]byte{1, 0, 0, 2}, "verify_ng", "none"},
		//   C(1.0.0.3): none, none          -> []  (no badge)
		{[]byte{1, 0, 0, 3}, "verify_ng", "none"},
		{[]byte{1, 0, 0, 3}, "verify_ng", "none"},
		// recent passers (per event):
		{[]byte{1, 0, 0, 9}, "bv_captcha_only", "header"},
		{[]byte{1, 0, 0, 10}, "bv_pow_then_captcha", "none"},
	}
	for i, s := range seed {
		if _, err := d.Exec(
			`INSERT INTO unmask_event
				(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
				 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			 VALUES ('','','','',?,'UA','','',0,?,0,0,'','',?,datetime('now','-20 minutes'))`,
			s.ipb, s.phase, `{"force_reason":"`+s.fr+`","score":1,"method":"behavioral"}`); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}

	ctx := context.Background()

	// verify_ng ranking: A > B/C by total, reasons distinct + none-folded.
	ng, err := VerifyNGRanking(ctx, d, "", nil, 36, 20)
	if err != nil {
		t.Fatalf("VerifyNGRanking: %v", err)
	}
	got := map[string][]string{}
	for _, r := range ng {
		got[r.IP] = r.ForceReasons
	}
	wants := map[string][]string{
		"1.0.0.1": {"stale"},
		"1.0.0.2": {"asn"},
	}
	for ip, want := range wants {
		if !reflect.DeepEqual(got[ip], want) {
			t.Errorf("VerifyNG[%s] reasons=%v want %v", ip, got[ip], want)
		}
	}
	if len(got["1.0.0.3"]) != 0 {
		t.Errorf("VerifyNG[1.0.0.3] all-none should be empty, got %v", got["1.0.0.3"])
	}

	// recent passers: per-event force_reason preserved verbatim ("none" kept
	// here; the template renders it as "-").
	rec, err := CaptchaPassRecent(ctx, d, "", nil, 36, 10)
	if err != nil {
		t.Fatalf("CaptchaPassRecent: %v", err)
	}
	frByIP := map[string]string{}
	for _, r := range rec {
		frByIP[r.IP] = r.ForceReason
	}
	if frByIP["1.0.0.9"] != "header" {
		t.Errorf("recent[1.0.0.9] force_reason=%q want header", frByIP["1.0.0.9"])
	}
	if frByIP["1.0.0.10"] != "none" {
		t.Errorf("recent[1.0.0.10] force_reason=%q want none", frByIP["1.0.0.10"])
	}
}
