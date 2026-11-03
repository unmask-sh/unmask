package ipgeo

import (
	"fmt"
	"testing"
)

// TestCacheHasACeiling: the answer cache holds at most two generations of
// genSize entries however many distinct addresses are looked up, and an
// address asked for again survives the turnover while a one-off leaves.
func TestCacheHasACeiling(t *testing.T) {
	r := Open(testCountryDB(t), "")
	defer r.Close()
	r.genSize = 8

	hot := "203.0.113.1"
	r.LookupInfo(hot)
	for i := 0; i < 100; i++ {
		// Unlisted addresses are cached too (as empty answers), so every
		// distinct address counts.
		r.LookupInfo(fmt.Sprintf("192.0.2.%d", i))
		if i%4 == 0 {
			r.LookupInfo(hot) // asked for again, so it is kept
		}
		if n := r.cacheLen(); n > 2*r.genSize {
			t.Fatalf("after %d lookups the cache holds %d entries, ceiling %d", i+2, n, 2*r.genSize)
		}
	}
	if _, ok := r.cacheGet(hot); !ok {
		t.Fatal("the address asked for throughout was dropped")
	}
	if _, ok := r.cacheGet("192.0.2.0"); ok {
		t.Fatal("an address seen once at the start is still held after two generations")
	}
	// The cache is a cache: an address it dropped is answered from the
	// database again, the same as before.
	if got := r.LookupInfo("203.0.113.1"); got.Country != "JP" {
		t.Fatalf("hot address: %+v", got)
	}
	r.Reload("", "")
	if n := r.cacheLen(); n != 0 {
		t.Fatalf("a reload kept %d cached answers", n)
	}
}
