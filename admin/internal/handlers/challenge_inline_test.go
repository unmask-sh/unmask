package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The challenge page must inline challenge.js rather than loading it as an
// external <script src>.  A client that can't fetch the external file renders
// the challenge but never runs the PoW, so it loops forever -- the widespread
// tool1-jp production loop (JS-load count was a fraction of the serve count).
func TestServeChallenge_InlinesJS(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	w := httptest.NewRecorder()
	h.ServeChallenge(w, req)

	body := w.Body.String()
	if strings.Contains(body, `src="/unmask/static/challenge.js`) {
		t.Error("challenge.js still loaded as an external <script src> -- a fetch failure loops the visitor")
	}
	if !strings.Contains(body, "_bv_set_ok") {
		t.Error("challenge.js was not inlined into the served challenge page")
	}
}
