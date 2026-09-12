package advisor

import (
	"context"
	"testing"
)

// A fingerprint candidate carries the challenge stages and the pass kinds
// like an address candidate does -- the herd row read "JS 0 · PoW 0 ·
// CAPTCHA 0" under 16 passes on tool1-us (operator, 2026-09-13) because the
// fingerprint query counted only serves and passes.
func TestJA4CandidateCarriesStagesAndPassKinds(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, MinScanner: 3, HerdMinIPs: 3, Limit: 50}
	// Six addresses, four serves each: 24 serves keep one pass under the
	// "passes constantly" cut (passes*20 <= serves).
	for i := 0; i < 6; i++ {
		ip := "198.51.100." + string(rune('1'+i))
		for j := 0; j < 4; j++ {
			insertEvent(t, d, ip, "t13d_stage", "serve", "Mozilla/5.0 (X11)", "")
		}
	}
	// One address ran the JavaScript twice (pow_then_captcha both times),
	// solved the proof-of-work, reached the CAPTCHA and completed it;
	// another solved the proof-of-work, reached the CAPTCHA and stopped
	// there.
	insertEvent(t, d, "198.51.100.1", "t13d_stage", "load", "Mozilla/5.0 (X11)", `{"chmode":"pow_then_captcha"}`)
	insertEvent(t, d, "198.51.100.1", "t13d_stage", "load", "Mozilla/5.0 (X11)", `{"chmode":"pow_then_captcha"}`)
	insertEvent(t, d, "198.51.100.1", "t13d_stage", "pow_pass", "Mozilla/5.0 (X11)", "")
	insertEvent(t, d, "198.51.100.1", "t13d_stage", "captcha", "Mozilla/5.0 (X11)", "")
	insertEvent(t, d, "198.51.100.1", "t13d_stage", "bv_pow_then_captcha", "Mozilla/5.0 (X11)", "")
	insertEvent(t, d, "198.51.100.2", "t13d_stage", "pow_pass", "Mozilla/5.0 (X11)", "")
	insertEvent(t, d, "198.51.100.2", "t13d_stage", "captcha", "Mozilla/5.0 (X11)", "")

	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	var herd *Candidate
	for i := range cands {
		if cands[i].Type == "ja4" && cands[i].Target == "t13d_stage" {
			herd = &cands[i]
		}
	}
	if herd == nil {
		t.Fatalf("the fingerprint herd is not a candidate: %+v", cands)
	}
	if herd.Serves != 24 || herd.Passes != 1 || herd.DistinctIPs != 6 {
		t.Errorf("herd counts: %+v", *herd)
	}
	if herd.Loads != 2 || herd.PowPassed != 2 || herd.CaptchaShown != 2 {
		t.Errorf("stages missing on the fingerprint row: loads=%d pow=%d captcha=%d", herd.Loads, herd.PowPassed, herd.CaptchaShown)
	}
	if herd.PassBoth != 1 || herd.PassPow != 0 || herd.PassCaptcha != 0 {
		t.Errorf("pass kinds missing on the fingerprint row: pow=%d captcha=%d both=%d", herd.PassPow, herd.PassCaptcha, herd.PassBoth)
	}
	// The chain presented, from the load beacon's chmode: pow_then_captcha
	// twice, the others never.
	if herd.ShownBoth != 2 || herd.ShownPow != 0 || herd.ShownCaptcha != 0 {
		t.Errorf("chains shown on the fingerprint row: pow=%d captcha=%d both=%d, want 0/0/2", herd.ShownPow, herd.ShownCaptcha, herd.ShownBoth)
	}
	// Its two gates: both proof-of-works cleared, one CAPTCHA of two completed.
	if herd.ChainPowPassed() != 2 || herd.ChainPowHeld() != 0 || herd.ChainCaptchaHeld() != 1 || herd.JSNotRun() != 22 {
		t.Errorf("chain outcome: pow passed=%d held=%d captcha held=%d js not run=%d, want 2/0/1/22",
			herd.ChainPowPassed(), herd.ChainPowHeld(), herd.ChainCaptchaHeld(), herd.JSNotRun())
	}
}
