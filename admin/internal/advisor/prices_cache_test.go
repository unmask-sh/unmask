package advisor

import (
	"math"
	"testing"
)

// The cost tells the prompt cache's tokens apart: a token read from it at a
// tenth of the input rate, one written at 1.25, the rest at the rate.  Cost
// without the split is the same call at the full rate.
func TestCostOfPricesTheCache(t *testing.T) {
	// claude-opus-5-5: $4 in / $20 out per million.
	usd, ok := CostOf("claude-opus-5-5", Usage{Input: 1_000_000, Output: 100_000, CacheRead: 500_000, CacheWrite: 200_000})
	if !ok {
		t.Fatal("no price")
	}
	want := (300_000*4.0 + 500_000*4.0*0.1 + 200_000*4.0*1.25 + 100_000*20.0) / 1e6
	if math.Abs(usd-want) > 1e-9 {
		t.Errorf("CostOf = %.6f, want %.6f", usd, want)
	}
	full, _ := Cost("claude-opus-5-5", 1_000_000, 100_000)
	if math.Abs(full-(4.0+2.0)) > 1e-9 {
		t.Errorf("Cost = %.6f, want 6", full)
	}
	// A cache larger than the input (a provider's miscount) is not a
	// negative charge.
	if usd, _ := CostOf("claude-opus-5-5", Usage{Input: 10, CacheRead: 20}); usd < 0 {
		t.Errorf("negative cost %v", usd)
	}
	if _, ok := CostOf("no-such-model", Usage{Input: 1}); ok {
		t.Error("an unknown model has a price")
	}
}
