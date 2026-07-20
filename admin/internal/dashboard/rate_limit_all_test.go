package dashboard

import (
	"context"
	"fmt"
	"testing"
)

// TestRateLimitAllSingleScan verifies the combined one-pass aggregation
// reproduces the four separate cards: only phase=serve + rl=1 rows count, IPs
// and paths rank by frequency, the query string is split off the path, and
// queries roll up per base path.
func TestRateLimitAllSingleScan(t *testing.T) {
	d := hiTestDB(t)
	ctx := context.Background()
	seed := func(ip []byte, path string, rl int, phase string) {
		pj := fmt.Sprintf(`{"rl":%d,"orig_path":%q}`, rl, path)
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
			 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			VALUES ('','','',0,?,'UA','','',0,?,0,0,'','',?,datetime('now','-10 minutes'))`,
			ip, phase, pj); err != nil {
			t.Fatal(err)
		}
	}
	ip1 := []byte{10, 0, 0, 1}
	ip2 := []byte{10, 0, 0, 2}
	ip3 := []byte{10, 0, 0, 3}
	// rl=1 serves (should all count):
	seed(ip1, "/api/x?a=1", 1, "serve")
	seed(ip1, "/api/x?a=1", 1, "serve")
	seed(ip1, "/api/x?a=1", 1, "serve")
	seed(ip1, "/api/x?a=2", 1, "serve")
	seed(ip2, "/api/y", 1, "serve")
	seed(ip2, "/api/y", 1, "serve")
	seed(ip3, "/api/x?a=1", 1, "serve")
	// must be excluded:
	seed(ip1, "/api/x?a=1", 0, "serve") // rl=0
	seed(ip1, "/api/x?a=1", 1, "load")  // wrong phase

	summary, ips, paths, byPath, err := RateLimitAll(ctx, d, "", nil, 24, 30, 30, 5)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 7 {
		t.Errorf("summary total = %d, want 7 rl=1 serves", summary.Total)
	}
	// IPs ranked by count: ip1=4, ip2=2, ip3=1.
	if len(ips) != 3 || ips[0].IP != "10.0.0.1" || ips[0].Count != 4 || ips[1].Count != 2 || ips[2].Count != 1 {
		t.Errorf("ip ranking = %+v, want ip1(4), ip2(2), ip3(1)", ips)
	}
	// Paths (query stripped): /api/x = 5 (a=1 ×4 + a=2 ×1), /api/y = 2.
	pc := map[string]int{}
	for _, p := range paths {
		pc[p.Path] = p.Count
	}
	if pc["/api/x"] != 5 || pc["/api/y"] != 2 {
		t.Errorf("path counts = %+v, want /api/x=5 /api/y=2", pc)
	}
	// Queries per path: /api/x -> {a=1: 4, a=2: 1}; /api/y has none.
	qx := map[string]int{}
	for _, q := range byPath["/api/x"] {
		qx[q.Query] = q.Count
	}
	if qx["a=1"] != 4 || qx["a=2"] != 1 {
		t.Errorf("queries for /api/x = %+v, want a=1:4 a=2:1", qx)
	}
	if len(byPath["/api/y"]) != 0 {
		t.Errorf("/api/y should have no query rows, got %+v", byPath["/api/y"])
	}
}

// TestRateLimitAllMariaFallbackShape: on a non-sqlite driver the function falls
// back to the four grouped queries; here we only assert the sqlite path returns
// a usable (non-nil map) shape for an empty DB so the template never nil-derefs.
func TestRateLimitAllEmpty(t *testing.T) {
	d := hiTestDB(t)
	summary, ips, paths, byPath, err := RateLimitAll(context.Background(), d, "", nil, 24, 30, 30, 5)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 0 || len(ips) != 0 || len(paths) != 0 || byPath == nil {
		t.Errorf("empty DB: got total=%d ips=%d paths=%d byPathNil=%v", summary.Total, len(ips), len(paths), byPath == nil)
	}
}
