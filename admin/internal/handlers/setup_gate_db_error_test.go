package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A user-count query that fails on a configured install (the write lock held
// past the busy timeout by a prune chunk, an aggregate) must not turn every
// admin page into a redirect to the setup wizard.  Once an admin has been
// seen the gate passes the request on; before one has been seen it answers
// 503 with Retry-After -- either way never the wizard.  Simulated by dropping
// the user table under the handler.
func TestSetupGateDBErrorIsNotAFreshInstall(t *testing.T) {
	h, _ := reconfHandler(t, true) // migrated, one superadmin
	passed := 0
	next := func(w http.ResponseWriter, r *http.Request) { passed++; w.WriteHeader(http.StatusTeapot) }
	gate := h.SetupGate(next)

	// Healthy: the admin is seen and the request passes.
	rr := httptest.NewRecorder()
	gate(rr, httptest.NewRequest(http.MethodGet, "/admin/", nil))
	if rr.Code != http.StatusTeapot || passed != 1 {
		t.Fatalf("configured install must pass through, got %d (passed=%d)", rr.Code, passed)
	}

	// The database stops answering.
	if _, err := h.DB.Exec(`DROP TABLE unmask_user`); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	gate(rr, httptest.NewRequest(http.MethodGet, "/admin/", nil))
	if rr.Code != http.StatusTeapot || passed != 2 {
		t.Fatalf("after an admin was seen, a failing count must still pass through (auth decides), got %d location=%q", rr.Code, rr.Header().Get("Location"))
	}
	if needed, step := h.SetupNeeded(httptest.NewRequest(http.MethodGet, "/admin/", nil)); needed {
		t.Errorf("SetupNeeded must not report %q on a configured install whose database is busy", step)
	}
}

func TestSetupGateDBErrorBeforeAnyAdminIs503(t *testing.T) {
	h, _ := reconfHandler(t, false) // migrated, no admin yet, no admin ever seen
	if _, err := h.DB.Exec(`DROP TABLE unmask_user`); err != nil {
		t.Fatal(err)
	}
	passed := 0
	gate := h.SetupGate(func(w http.ResponseWriter, r *http.Request) { passed++ })
	rr := httptest.NewRecorder()
	gate(rr, httptest.NewRequest(http.MethodGet, "/admin/hunt/", nil))
	if rr.Code != http.StatusServiceUnavailable || passed != 0 {
		t.Fatalf("a database that cannot answer must be a 503, not %d (passed=%d, location=%q)", rr.Code, passed, rr.Header().Get("Location"))
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Errorf("503 must carry Retry-After")
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Errorf("must not redirect (to the wizard or anywhere), got %q", loc)
	}
}
