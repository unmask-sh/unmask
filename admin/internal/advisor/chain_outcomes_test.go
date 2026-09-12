package advisor

import "testing"

// The traffic cell's chain arithmetic (operator's design, 2026-09-13): each
// chain reads shown → passed · not completed, pow_then_captcha its two gates
// each, and JS how many were served and left without running it.
func TestCandidateChainOutcomes(t *testing.T) {
	c := Candidate{Serves: 40, Loads: 38, ShownPow: 30, ShownBoth: 8,
		PowPassed: 33, CaptchaShown: 5, Passes: 30, PassPow: 28, PassBoth: 2}
	if c.JSNotRun() != 2 {
		t.Errorf("served 40, ran 38: not run = %d, want 2", c.JSNotRun())
	}
	if c.PowOnlyHeld() != 2 || !c.HasPowOnly() {
		t.Errorf("pow_only shown 30, passed 28: held = %d, want 2", c.PowOnlyHeld())
	}
	if c.CaptchaOnlyHeld() != 0 || c.HasCaptchaOnly() {
		t.Errorf("captcha_only never shown: held = %d, has = %v", c.CaptchaOnlyHeld(), c.HasCaptchaOnly())
	}
	// 33 solves in all, 28 of them pow_only passes: 5 cleared the chain's
	// proof-of-work, 3 of 8 stopped there; 2 CAPTCHAs completed, 3 not.
	if c.ChainPowPassed() != 5 || c.ChainPowHeld() != 3 || c.ChainCaptchaHeld() != 3 || !c.HasChain() {
		t.Errorf("pow_then_captcha: pow passed=%d held=%d, captcha held=%d, want 5/3/3",
			c.ChainPowPassed(), c.ChainPowHeld(), c.ChainCaptchaHeld())
	}
	// Every line closes: shown = passed + not completed.
	if c.ShownPow != c.PassPow+c.PowOnlyHeld() || c.ShownBoth != c.ChainPowPassed()+c.ChainPowHeld() || c.ChainPowPassed() != c.PassBoth+c.ChainCaptchaHeld() {
		t.Error("a chain line must close: shown = passed + not completed")
	}

	// A node that recorded passes but served nothing (the load-balanced
	// fleet: another node served the page): the chain still has its line,
	// and no figure goes negative.
	d := Candidate{Passes: 16, PassPow: 16, PowPassed: 16}
	if d.JSNotRun() != 0 || d.PowOnlyHeld() != 0 || !d.HasPowOnly() || d.HasChain() || d.HasCaptchaOnly() {
		t.Errorf("passes without a page served: not run=%d held=%d has pow_only=%v chain=%v captcha_only=%v",
			d.JSNotRun(), d.PowOnlyHeld(), d.HasPowOnly(), d.HasChain(), d.HasCaptchaOnly())
	}
}

// The escalation reasons: the rules by serves, the ordinary path last, and
// no line for a client the ordinary path alone served.
func TestReasonOrder(t *testing.T) {
	rs := []ReasonCount{{Reason: "", Serves: 50}, {Reason: "geo", Serves: 3}, {Reason: "asn", Serves: 40}, {Reason: "rate_limit", Serves: 3}}
	sortReasons(rs)
	want := []ReasonCount{{Reason: "asn", Serves: 40}, {Reason: "geo", Serves: 3}, {Reason: "rate_limit", Serves: 3}, {Reason: "", Serves: 50}}
	for i := range want {
		if rs[i] != want[i] {
			t.Fatalf("order: got %+v, want %+v", rs, want)
		}
	}
	if !(Candidate{Reasons: rs}).Escalated() {
		t.Error("a rule served some of the challenges: escalated")
	}
	if (Candidate{Reasons: []ReasonCount{{Reason: "", Serves: 9}}}).Escalated() || (Candidate{}).Escalated() {
		t.Error("the ordinary path alone, or nothing recorded: not escalated")
	}
}
