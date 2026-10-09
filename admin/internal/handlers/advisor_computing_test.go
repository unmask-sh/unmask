package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
)

// The candidates page answers at once while its list is being computed.
//
// Extracting candidates is a pass over the whole window; on a large install
// the page that waited for it ran past the server's write timeout and showed
// nothing.  With no list yet the page must render, say the list is being
// computed, and offer the status the script polls; once the list has landed
// the page shows it without the notice.
func TestAdvisorPageWhileComputing(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	h.SetSettings(cur)
	advisor.ResetCandidateCache()
	defer advisor.SetComputeWaitForTest(0)()

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil)
	rr := httptest.NewRecorder()
	h.AdminAdvisorIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `id="adv-computing"`) {
		t.Fatal("the page did not say the list is being computed")
	}
	if strings.Contains(rr.Body.String(), `class="kv cand-age"`) {
		t.Error("a list that does not exist yet must not be described as stale")
	}

	// The status the page polls, until the list lands.
	deadline := time.Now().Add(10 * time.Second)
	for {
		sr := httptest.NewRecorder()
		h.AdminAdvisorStatus(sr, httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/status?window=24", nil))
		var st struct {
			Computing bool   `json:"computing"`
			Ready     bool   `json:"ready"`
			Error     string `json:"error"`
		}
		if err := json.Unmarshal(sr.Body.Bytes(), &st); err != nil {
			t.Fatalf("status json: %v (%s)", err, sr.Body.String())
		}
		if st.Ready {
			break
		}
		if st.Error != "" || time.Now().After(deadline) {
			t.Fatalf("the list did not land: %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}

	rr = httptest.NewRecorder()
	h.AdminAdvisorIndex(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d after the list landed", rr.Code)
	}
	if strings.Contains(rr.Body.String(), `id="adv-computing"`) {
		t.Error("the notice stayed after the list landed")
	}
}
