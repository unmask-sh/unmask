package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The /metrics allowlist is checked against the address the admin gate
// resolves (adminClientIP): X-Real-IP counts only off a trusted proxy.  It
// used to take the header from anyone, so a client reaching the daemon
// directly could name 127.0.0.1 and read the traffic and verdict counters.
func TestMetricsGateReadsTheAddressOffTheConnection(t *testing.T) {
	h := newTestHandler(t)
	get := func(peer, realIP string) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/unmask/metrics", nil)
		r.RemoteAddr = peer
		if realIP != "" {
			r.Header.Set("X-Real-IP", realIP)
		}
		rr := httptest.NewRecorder()
		h.Metrics(rr, r)
		return rr.Code
	}

	// Direct from outside, naming loopback in the header: refused.
	if code := get("203.0.113.9:5555", "127.0.0.1"); code != http.StatusForbidden {
		t.Errorf("outside peer with X-Real-IP 127.0.0.1: %d, want 403", code)
	}
	// Direct from outside, no header: refused (the default list is loopback).
	if code := get("203.0.113.9:5555", ""); code != http.StatusForbidden {
		t.Errorf("outside peer: %d, want 403", code)
	}
	// From the proxy on loopback, no client named: served.
	if code := get("127.0.0.1:5555", ""); code != http.StatusOK {
		t.Errorf("loopback peer: %d, want 200", code)
	}
	// The proxy relays a client from outside: refused.
	if code := get("127.0.0.1:5555", "203.0.113.9"); code != http.StatusForbidden {
		t.Errorf("loopback proxy relaying an outside client: %d, want 403", code)
	}
	// The proxy relays a client from loopback: served.
	if code := get("127.0.0.1:5555", "127.0.0.1"); code != http.StatusOK {
		t.Errorf("loopback proxy relaying a loopback client: %d, want 200", code)
	}
}
