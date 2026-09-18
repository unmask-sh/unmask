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
		TopUAs:  []UACount{{UA: "curl/8", Requests: 30}, {UA: "Mozilla/5.0", Requests: 8}, {UA: "python-requests/2", Requests: 4}, {UA: "wget/1", Requests: 2}, {UA: "Go-http-client/1.1", Requests: 1}}, DistinctUAs: 7,
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
		`"user_agents":[{"ua":"curl/8","requests":30},{"ua":"Mozilla/5.0","requests":8},{"ua":"python-requests/2","requests":4}]`, `"distinct_user_agents":7`,
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
	// The bundle carries the three most frequent user agents, not the five
	// the page lists (tokens on every row of the pool).
	if strings.Contains(s, "wget/1") {
		t.Error("the bundle carries at most three user agents per row")
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

// The challenge holds a client that completes a token few of its challenges
// as surely as one that completes none: the row scores like a contained one
// and sorts under every row that really gets through.  Operator's
// calibration (2026-09-14): "通過率が1%未満かつ100以下の場合はもっとスコアを
// 下げた方がいいかも 通過0は特に下げる".
func TestNearlyContainedIsHeldLikeContained(t *testing.T) {
	cases := []struct {
		name           string
		passes, serves int
		nearly         bool
	}{
		{"a herd that passed nine times in eighteen thousand", 9, 18316, true},
		{"seventy-nine passes in fourteen thousand", 79, 13897, true},
		{"one pass in a thousand", 1, 1332, true},
		{"exactly one percent is not under it", 20, 2000, false},
		{"just under one percent", 20, 2001, true},
		{"the absolute cap: a hundred passes still held", 100, 10001, true},
		{"over the cap, however small the rate", 101, 1000000, false},
		{"a real visitor", 10, 11, false},
		{"never passed is contained, not nearly", 0, 500, false},
		{"a pass whose challenge landed on another node", 3, 0, false},
	}
	for _, tc := range cases {
		c := Candidate{Passes: tc.passes, Serves: tc.serves, Requests: tc.serves}
		c.Contained = tc.passes == 0
		if got := c.NearlyContained(); got != tc.nearly {
			t.Errorf("%s: NearlyContained = %v, want %v", tc.name, got, tc.nearly)
		}
		if got, want := c.ChallengeHolds(), tc.nearly || tc.passes == 0; got != want {
			t.Errorf("%s: ChallengeHolds = %v, want %v", tc.name, got, want)
		}
	}
	// A hundred passes is the cap, so 100 in 10,001 is over it by one: the
	// rate is under a percent but the sessions are real.
	if !nearlyContained(100, 10100) {
		t.Error("a hundred passes at under a percent is still held")
	}
	if nearlyContained(100, 10000) {
		t.Error("exactly one percent is not under one percent")
	}
}

// The score: a held row is capped at the candidate floor, or lifted to the
// contained cost score once its volume is a cost on its own -- the same two
// numbers a never-passing row gets, so a stray completion no longer buys a
// row the full weight of its signals.
func TestNearlyContainedScoresLikeContained(t *testing.T) {
	// Signals worth five: a fingerprint herd at volume.
	mk := func(passes, serves, requests int) Candidate {
		c := Candidate{Type: "ja4", Target: "t13d_x", Passes: passes, Serves: serves, Requests: requests, DistinctIPs: 3000}
		c.Contained = passes == 0
		c.fingerprintSignals(Options{}.resolved())
		c.settleScore()
		return c
	}
	big := mk(9, 18316, 20551) // past the contained cost floor
	if !big.NearlyContained() || big.Score != containedCostScore {
		t.Errorf("a held herd at volume: nearly=%v score=%d want %d", big.NearlyContained(), big.Score, containedCostScore)
	}
	small := mk(2, 2298, 2300) // short of it
	if small.Score != candidateFloor || small.Attention() {
		t.Errorf("a held herd short of the cost floor: score=%d attention=%v", small.Score, small.Attention())
	}
	passing := mk(20, 1792, 1835) // 1.12%: over the line, scored on its evidence
	if passing.NearlyContained() || passing.Score < AttentionScore {
		t.Errorf("a herd that really passes: nearly=%v score=%d", passing.NearlyContained(), passing.Score)
	}
	// And the order: passing, then nearly, then never.
	none := mk(0, 18316, 20551)
	rows := []Candidate{none, big, passing}
	SortByAttention(rows)
	if rows[0].Passes != 20 || rows[1].Passes != 9 || rows[2].Passes != 0 {
		t.Errorf("order: %d %d %d, want 20 9 0", rows[0].Passes, rows[1].Passes, rows[2].Passes)
	}
	// The nomination gate follows the same rule.
	if !HeldBelowCost(2, 2298, 2300) {
		t.Error("a nearly contained pool row short of the cost floor must not be nominated")
	}
	if HeldBelowCost(9, 18316, 20551) {
		t.Error("past the cost floor the volume itself is the reason to list it")
	}
	if HeldBelowCost(20, 1792, 1835) {
		t.Error("a row that really passes is not held")
	}
}

// A cloud address that completes the challenge is a server farm only when one
// client is behind it.  Several user agents over several fingerprints is a
// proxy -- a company gateway, a VPN exit -- and the people behind it are not
// what a rule against the address would stop.  Operator's question
// (2026-09-15): a cloud address can be the proxy of a legitimate visitor.
func TestPassingHostingYieldsToASharedEgress(t *testing.T) {
	mk := func(uas, ja4s int) Candidate {
		c := Candidate{Type: "ip", Target: "203.0.113.5", ASNOrg: "Amazon Technologies Inc.",
			UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", Passes: 10, Serves: 12, Requests: 40,
			DistinctUAs: uas, DistinctJA4s: ja4s}
		c.addressSignals(Options{}.resolved())
		c.settleScore()
		return c
	}
	one := mk(1, 1) // one browser, one TLS stack: the farm shape
	if !hasSig(one, "passing_hosting") || hasSig(one, "shared_egress") || one.SharedEgress() {
		t.Errorf("one client behind the address is still a passing hosting farm: %+v", one.Signals)
	}
	if !one.Attention() || one.Score != 6 {
		t.Errorf("the farm keeps its weight: score %d", one.Score)
	}
	gateway := mk(13, 3) // a floor of employees behind a security gateway
	if !gateway.SharedEgress() || hasSig(gateway, "passing_hosting") || !hasSig(gateway, "shared_egress") {
		t.Errorf("a gateway with people behind it is not a passing farm: %+v", gateway.Signals)
	}
	if gateway.Attention() || gateway.Score != 3 {
		t.Errorf("the gateway drops out of the default view: score %d", gateway.Score)
	}
	// A crawler that rotates user agents keeps one TLS stack: not this shape.
	if rotating := mk(13, 1); rotating.SharedEgress() || !hasSig(rotating, "passing_hosting") {
		t.Errorf("user agents over a single fingerprint is one client rotating names: %+v", rotating.Signals)
	}
	// Two user agents is a phone and a laptop, not a floor of them.
	if pair := mk(2, 2); pair.SharedEgress() || !hasSig(pair, "passing_hosting") {
		t.Errorf("two user agents is not yet a proxy: %+v", pair.Signals)
	}
	// Outside a hosting network neither signal applies.
	home := Candidate{Type: "ip", Target: "203.0.113.6", ASNOrg: "Some Telecom", UA: "Mozilla/5.0 (Windows NT 10.0)",
		Passes: 10, Serves: 12, Requests: 40, DistinctUAs: 13, DistinctJA4s: 3}
	home.addressSignals(Options{}.resolved())
	if hasSig(home, "shared_egress") || hasSig(home, "passing_hosting") || hasSig(home, "hosting_network") {
		t.Errorf("an ordinary network carries none of these: %+v", home.Signals)
	}
}

func hasSig(c Candidate, id string) bool {
	for _, s := range c.Signals {
		if s.ID == id {
			return true
		}
	}
	return false
}

// The fingerprint's verdict reaches the row from the candidate pass itself.
// It used to come from a separate read of the whole week, which on a busy
// node meant grouping most of the table by verdict to learn one word.  A
// fingerprint's verdict is a function of the fingerprint, so the group's
// maximum is that word exactly.
func TestFingerprintRowCarriesItsVerdict(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	for i := 1; i <= 12; i++ {
		insertEvents(t, d, "198.51.100."+itoa(i), "t13d_verdicted", "serve", "curl/8", "", 3)
	}
	if _, err := d.Exec(`UPDATE unmask_event SET ja4_verdict = 'bot_curl' WHERE ja4 = 't13d_verdicted'`); err != nil {
		t.Fatal(err)
	}
	// A fingerprint whose serves carry no verdict must read as none, not as
	// the neighbouring row's.
	for i := 1; i <= 12; i++ {
		insertEvents(t, d, "203.0.113."+itoa(i), "t13d_plain", "serve", "curl/8", "", 3)
	}
	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Candidate{}
	for _, c := range cands {
		by[c.Target] = c
	}
	if got := by["t13d_verdicted"].Verdict; got != "bot_curl" {
		t.Errorf("verdict = %q, want bot_curl", got)
	}
	if got := by["t13d_plain"].Verdict; got != "" {
		t.Errorf("a fingerprint with no verdict reads as %q", got)
	}
	// An address row has no fingerprint verdict of its own.
	insertEvents(t, d, "203.0.113.200", "t13d_verdicted", "serve", "curl/8", "", 40)
	cands, err = Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.Type == "ip" && c.Verdict != "" {
			t.Errorf("address %s carries a fingerprint verdict %q", c.Target, c.Verdict)
		}
	}
}
