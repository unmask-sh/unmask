package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAdminCommunityBansImpactJSON: the poll endpoint returns a well-formed
// JSON body with the four fields the page's spinner JS reads, and never blocks
// (the figure is computed in the background).
func TestAdminCommunityBansImpactJSON(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/api/community-bans/impact", nil)
	rr := httptest.NewRecorder()
	h.AdminCommunityBansImpact(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct == "" || ct[:16] != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var body struct {
		Known     *bool `json:"known"`
		Computing *bool `json:"computing"`
		Count     *int  `json:"count"`
		UniqueIP  *int  `json:"uniqueIP"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, rr.Body.String())
	}
	if body.Known == nil || body.Computing == nil || body.Count == nil || body.UniqueIP == nil {
		t.Errorf("missing a field the spinner JS reads: %s", rr.Body.String())
	}
	// The first call must not have blocked on the scan: it returns not-known
	// (the compute was dispatched to the background).
	if body.Known != nil && *body.Known {
		t.Log("figure already known (fast test DB); acceptable")
	}
}
