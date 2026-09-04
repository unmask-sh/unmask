package advisor

import (
	"context"
	"sync/atomic"
	"testing"
)

// The pool is the wider ranking the model may nominate from: it must carry
// the evidence columns and the origin decoration, and it must never contain
// what the exclusions rule out.
func TestBuildPool(t *testing.T) {
	d := newTestDB(t)
	// A busy public address that passes: the shape the engine cannot flag.
	for i := 0; i < 8; i++ {
		insertEvent(t, d, "198.51.100.7", "t13d_pool", "serve", "Mozilla/5.0 (X11)", `{"path":"/"}`)
	}
	for i := 0; i < 3; i++ {
		insertEvent(t, d, "198.51.100.7", "t13d_pool", "bv_pow_only", "Mozilla/5.0 (X11)", "")
	}
	// Two more addresses on the same fingerprint.
	insertEvent(t, d, "198.51.100.8", "t13d_pool", "serve", "Mozilla/5.0 (X11)", "")
	insertEvent(t, d, "198.51.100.9", "t13d_pool", "serve", "Mozilla/5.0 (X11)", "")
	// Excluded shapes: banned, private.
	for i := 0; i < 5; i++ {
		insertEvent(t, d, "203.0.113.40", "t13d_ban", "serve", "curl/8", "")
		insertEvent(t, d, "10.0.0.5", "t13d_priv", "serve", "curl/8", "")
	}

	var calls int32
	orig := LookupPTR
	LookupPTR = func(ctx context.Context, ip string) []string {
		atomic.AddInt32(&calls, 1)
		if ip == "198.51.100.7" {
			return []string{"vm7.examplecloud.test."}
		}
		return nil
	}
	t.Cleanup(func() { LookupPTR = orig })
	// The package cache outlives tests; start this one from a clean slate.
	ptrCache.Lock()
	ptrCache.m = map[string]ptrEntry{}
	ptrCache.Unlock()

	excl := Exclusions{BannedIPs: map[string]bool{"203.0.113.40": true}}
	pool, err := BuildPool(context.Background(), d, nil, excl, Options{})
	if err != nil {
		t.Fatal(err)
	}

	var busy *PoolIP
	for i := range pool.IPs {
		switch pool.IPs[i].IP {
		case "198.51.100.7":
			busy = &pool.IPs[i]
		case "203.0.113.40", "10.0.0.5":
			t.Errorf("excluded address in the pool: %s", pool.IPs[i].IP)
		}
	}
	if busy == nil {
		t.Fatalf("the busy address is missing from the pool: %+v", pool.IPs)
	}
	if busy.Serves != 8 || busy.Passes != 3 || busy.UA != "Mozilla/5.0 (X11)" {
		t.Errorf("evidence columns wrong: %+v", *busy)
	}
	if busy.RDNS != "vm7.examplecloud.test." {
		t.Errorf("reverse DNS not attached: %+v", *busy)
	}
	if !pool.hasJA4("t13d_pool") {
		t.Errorf("fingerprint pool is missing the shared JA4: %+v", pool.JA4s)
	}
	for _, j := range pool.JA4s {
		if j.JA4 == "t13d_pool" && j.DistinctIPs != 3 {
			t.Errorf("distinct addresses for the shared JA4 = %d, want 3", j.DistinctIPs)
		}
	}
	var uaFound bool
	for _, u := range pool.UAs {
		if u.UA == "Mozilla/5.0 (X11)" {
			uaFound = true
			if u.DistinctIPs != 3 {
				t.Errorf("distinct addresses for the UA = %d, want 3", u.DistinctIPs)
			}
		}
	}
	if !uaFound {
		t.Errorf("user-agent pool is missing the browser UA: %+v", pool.UAs)
	}

	// A second build within the TTL must not ask the resolver again.
	before := atomic.LoadInt32(&calls)
	if _, err := BuildPool(context.Background(), d, nil, excl, Options{}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&calls) != before {
		t.Errorf("reverse DNS was looked up again despite the cache (%d -> %d)", before, calls)
	}
}
