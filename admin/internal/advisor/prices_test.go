package advisor

import "testing"

func TestPriceLookup(t *testing.T) {
	cases := []struct {
		model   string
		in, out float64
		ok      bool
	}{
		{"claude-haiku-5-5", 0.10, 0.50, true},
		{"claude-opus-4-5-20251101", 5, 25, true},  // the dated id
		{"claude-3-5-sonnet-latest", 3, 15, true},  // the -latest alias
		{"claude-opus-4-1-20250805", 15, 75, true}, // the longer key, not claude-opus-4
		{"gpt-5-mini-2025-08-07", 0.25, 2, true},   // date in the other form
		{"gpt-5.2", 1.75, 14, true},                // gpt-5 does not stand in
		{"gpt-5-chat-latest", 1.25, 10, true},      // gpt-5 does, for its dash-joined variants
		{"o4-mini-2025-04-16", 1.10, 4.40, true},   // o-series
		{"Claude-Sonnet-5-5", 2, 10, true},         // case
		{"llama3.2", 0, 0, false},                  // a local model
		{"gpt-oss:20b", 0, 0, false},               // a local model with a gpt- prefix
		{"claude-opus-9", 0, 0, false},             // newer than the table
		{"", 0, 0, false},
	}
	for _, c := range cases {
		p, ok := PriceFor(c.model)
		if ok != c.ok || p.In != c.in || p.Out != c.out {
			t.Errorf("%q: got %+v %v, want %v/%v %v", c.model, p, ok, c.in, c.out, c.ok)
		}
	}
}

func TestCostAndFormat(t *testing.T) {
	// A haiku answer: 59,340 in at $0.10/M and 2,219 out at $0.50/M.
	usd, ok := Cost("claude-haiku-5-5", 59340, 2219)
	if !ok || usd < 0.00704 || usd > 0.00705 {
		t.Fatalf("haiku: %v %v", usd, ok)
	}
	if _, ok := Cost("e2e-model", 10, 10); ok {
		t.Error("an unknown model has a cost")
	}
	for _, c := range []struct {
		usd  float64
		want string
	}{
		{0.0070435, "$0.007"},
		{0.281, "$0.28"},
		{3.2149, "$3.21"},
		{0.1, "$0.10"},
		{0.0005, "$0.001"},
		{0.0004, "<$0.001"},
		{0, "<$0.001"},
	} {
		if got := FormatUSD(c.usd); got != c.want {
			t.Errorf("%v: %q, want %q", c.usd, got, c.want)
		}
	}
}
