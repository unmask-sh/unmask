package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /readyz says whether the daemon has its database: 503 without one --
// whether the install is waiting for it or was never set up -- and 200 with
// one, without asking it anything.
func TestReadyz(t *testing.T) {
	probe := func(h *Handler) (int, string) {
		rr := httptest.NewRecorder()
		h.Readyz(rr, httptest.NewRequest(http.MethodGet, "/unmask/readyz", nil))
		return rr.Code, rr.Body.String()
	}
	if code, body := probe(&Handler{}); code != http.StatusServiceUnavailable || body != "database unavailable\n" {
		t.Errorf("without a database: %d %q, want 503 %q", code, body, "database unavailable\n")
	}
	h, _ := reconfHandler(t, true)
	if code, body := probe(h); code != http.StatusOK || body != "ok\n" {
		t.Errorf("with a database: %d %q, want 200 %q", code, body, "ok\n")
	}
	// Still 200 when the database has stopped answering: the pool finds it
	// again, and the probe is not what takes a node out for it.
	_ = h.DB.Close()
	if code, _ := probe(h); code != http.StatusOK {
		t.Errorf("with a database that does not answer now: %d, want 200", code)
	}
}
