package advisor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

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

// The user agents a row lists: the most frequent first, at most topUAs of
// them, and the remainder counted.
func TestTopUAsAreTheMostFrequent(t *testing.T) {
	d := newTestDB(t)
	for i := 0; i < 8; i++ {
		ua := "ua-" + string(rune('a'+i))
		for j := 0; j <= i; j++ { // ua-a once ... ua-h eight times
			insertEvent(t, d, "198.51.100.60", "t13d_ua", "serve", ua, "")
		}
	}
	insertEvent(t, d, "198.51.100.60", "t13d_ua", "serve", "", "") // no user agent: not one
	f, err := keyFacets(context.Background(), d, "ip_address", packedIPs([]string{"198.51.100.60"}), 60)
	if err != nil {
		t.Fatal(err)
	}
	row := f["198.51.100.60"]
	if row.DistinctUAs != 8 || len(row.TopUAs) != topUAs || row.TopUAs[0] != (UACount{UA: "ua-h", Requests: 8}) || row.TopUAs[4] != (UACount{UA: "ua-d", Requests: 4}) {
		t.Errorf("top user agents: %+v distinct=%d", row.TopUAs, row.DistinctUAs)
	}
	c := Candidate{TopUAs: row.TopUAs, DistinctUAs: row.DistinctUAs}
	if c.MoreUAs() != 3 {
		t.Errorf("more = %d, want 3", c.MoreUAs())
	}
	// All serves on the ordinary path: one reason, "", and not escalated.
	if len(row.Reasons) != 1 || !row.Reasons[0].None() || row.Reasons[0].Serves != 37 || (Candidate{Reasons: row.Reasons}).Escalated() {
		t.Errorf("reasons: %+v", row.Reasons)
	}
}

// The model reads a row the way the operator's page shows it: the challenge
// by chain with every difference taken, the escalation reasons with "none"
// spelled out, the user agents and the paths with their counts (operator,
// 2026-09-13: "ここまでの改修で使えそうな情報は AI に渡すようにして").
func TestBundleReadsLikeTheRow(t *testing.T) {
	c := Candidate{Type: "ip", Target: "203.0.113.9", Serves: 40, Loads: 38, Passes: 30,
		ShownPow: 30, ShownBoth: 8, PowPassed: 33, CaptchaShown: 5, PassPow: 28, PassBoth: 2,
		Reasons: []ReasonCount{{Reason: "asn", Serves: 30}, {Reason: "", Serves: 10}},
		TopUAs:  []UACount{{UA: "curl/8", Requests: 30}, {UA: "Mozilla/5.0", Requests: 8}}, DistinctUAs: 3,
		Paths: []PathCount{{Path: "/wp-login.php", Hits: 25, Site: "example.test", Scheme: "https", Port: 443}}, DistinctPaths: 12,
		RDNS: "vm9.examplecloud.test.", ASNOrg: "ExampleCloud", Country: "US",
		Signals: []Signal{{ID: "scanner_paths"}}}
	b, err := json.Marshal(buildBundle([]Candidate{c}))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"js_ran":38`, `"js_not_run":2`,
		`"chains":{"pow_only":{"shown":30,"passed":28,"not_completed":2},"pow_then_captcha":{"shown":8,"pow_passed":5,"pow_not_completed":3,"captcha_passed":2,"captcha_not_completed":3}}`,
		`"escalation_reasons":[{"reason":"asn","serves":30},{"reason":"none","serves":10}]`,
		`"user_agents":[{"ua":"curl/8","requests":30},{"ua":"Mozilla/5.0","requests":8}]`, `"distinct_user_agents":3`,
		`"paths":[{"path":"/wp-login.php","hits":25}]`, `"distinct_paths":12`,
		`"reverse_dns":"vm9.examplecloud.test."`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("bundle lacks %s:\n%s", want, s)
		}
	}
	// A fingerprint's collateral is named for what it is (the model quoted
	// "pass_ips_7d" in its reviews; operator, 2026-09-13: "何を意味するのか
	// 分かりづらい").
	fp := Candidate{Type: "ja4", Target: "t13d_x", PassIPs7d: 3}
	if b, _ := json.Marshal(buildBundle([]Candidate{fp})); !strings.Contains(string(b), `"addresses_passed_7d":3`) || strings.Contains(string(b), "pass_ips_7d") {
		t.Errorf("fingerprint collateral: %s", b)
	}
	for _, gone := range []string{"shown_pow_only", "pass_pow", "sample_paths", "js_loaded", "captcha_only", `"site"`} {
		if strings.Contains(s, gone) {
			t.Errorf("bundle still carries %s:\n%s", gone, s)
		}
	}
	// A row from before the counts still names its one user agent and its
	// sample paths, uncounted.
	old := Candidate{Type: "ip", Target: "203.0.113.10", UA: "python-requests/2.31", SamplePaths: []string{"/.env"}}
	b, _ = json.Marshal(buildBundle([]Candidate{old}))
	if !strings.Contains(string(b), `"user_agents":[{"ua":"python-requests/2.31","requests":0}]`) || !strings.Contains(string(b), `"paths":[{"path":"/.env"}]`) {
		t.Errorf("an uncounted row: %s", b)
	}
	// The pool rows read the same: chains folded, the raw counts not sent.
	p := PoolIP{IP: "203.0.113.9", Serves: 40, JSLoaded: 38, Passes: 30, ShownPow: 30, PowPassed: 30, PassPow: 30, UA: "curl/8"}
	p.Chains = chainStats(p.ShownPow, p.ShownCaptcha, p.ShownBoth, p.PowPassed, p.PassPow, p.PassCaptcha, p.PassBoth)
	p.JSNotRun = floor0(p.Serves - p.JSLoaded)
	b, _ = json.Marshal(p)
	if !strings.Contains(string(b), `"js_ran":38,"js_not_run":2`) || !strings.Contains(string(b), `"chains":{"pow_only":{"shown":30,"passed":30,"not_completed":0}}`) || strings.Contains(string(b), "shown_pow_only") || strings.Contains(string(b), `"user_agent"`) {
		t.Errorf("pool row: %s", b)
	}
	// "none" on the wire round-trips to "" in memory (stored picks).
	var back []ReasonCount
	if err := json.Unmarshal([]byte(`[{"reason":"none","serves":3},{"reason":"geo","serves":1}]`), &back); err != nil || len(back) != 2 || !back[0].None() || back[1].Reason != "geo" {
		t.Errorf("reasons round trip: %+v %v", back, err)
	}
	if chainStats(0, 0, 0, 0, 0, 0, 0) != nil {
		t.Error("no chain presented or completed: no chains object")
	}
}
