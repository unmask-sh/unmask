package advisor

import (
	"context"
	"testing"
)

// The collateral of a fingerprint ban: how many addresses got through the
// challenge with it in the last week, graded none / some / block.
func TestJA4Collateral(t *testing.T) {
	d := newTestDB(t)
	// A herd that never passes: three addresses, serves only.
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		insertEvent(t, d, ip, "t13d_herd", "serve", "curl/8", "")
	}
	// A shared browser fingerprint: real visitors pass with it.
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		insertEvent(t, d, ip, "t13d_browser", "serve", "Mozilla/5.0 (iPhone)", "")
		if i < 2 {
			insertEvent(t, d, ip, "t13d_browser", "bv_pow_only", "Mozilla/5.0 (iPhone)", "")
		}
	}
	herd, err := JA4Collateral(context.Background(), d, "t13d_herd")
	if err != nil {
		t.Fatal(err)
	}
	if herd.IPs != 3 || herd.Passes != 0 || herd.PassIPs != 0 || herd.Level != "none" || len(herd.PassUAs) != 0 {
		t.Errorf("herd: %+v", herd)
	}
	br, err := JA4Collateral(context.Background(), d, "t13d_browser")
	if err != nil {
		t.Fatal(err)
	}
	if br.IPs != 3 || br.Passes != 2 || br.PassIPs != 2 || br.Level != "some" || len(br.PassUAs) != 1 || br.PassUAs[0] != "Mozilla/5.0 (iPhone)" {
		t.Errorf("browser: %+v", br)
	}
	// Enough passers and a ban is refused outright.
	for i := 10; i < 10+collateralAckMax; i++ {
		insertEvent(t, d, "198.51.100."+itoa(i), "t13d_common", "bv_captcha_only", "Mozilla/5.0", "")
	}
	common, err := JA4Collateral(context.Background(), d, "t13d_common")
	if err != nil {
		t.Fatal(err)
	}
	if common.PassIPs != collateralAckMax || common.Level != "block" {
		t.Errorf("common: %+v", common)
	}
	if unknown, err := JA4Collateral(context.Background(), d, "t13d_nobody"); err != nil || unknown.Level != "none" || unknown.IPs != 0 {
		t.Errorf("unknown fingerprint: %+v %v", unknown, err)
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}
