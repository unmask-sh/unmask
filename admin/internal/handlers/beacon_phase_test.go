package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The beacon endpoint takes the phases the challenge page reports.  serve,
// check and the rebinds are the daemon's own records, and the statistics
// count a serve under whatever reason it carries: with a page's token a
// client could write "serve" rows with a reason of its choosing, each new
// reason a rollup row kept for a month.  And the flags are a few known bits,
// not any number the client sends: the rollup keys a row and a sketch by the
// value.
func TestBeaconTakesThePagesPhasesAndTheKnownFlags(t *testing.T) {
	h := newTestHandler(t)
	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/unmask/api/debug", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Real-IP", "198.51.100.7")
		rr := httptest.NewRecorder()
		h.DebugBeacon(rr, req)
		return rr.Code
	}
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase)
	for _, phase := range []string{"serve", "check", "bv_rebind", "bv_rebind_reject"} {
		if code := post(`{"phase":"` + phase + `","force_reason":"made_up_1","bt":"` + bt + `"}`); code != http.StatusBadRequest {
			t.Errorf("a beacon claiming the daemon's phase %q: %d, want 400", phase, code)
		}
	}
	var n int
	if err := h.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d rows were written for refused phases", n)
	}

	// The page's own phases still go through, with the flags held to their bits.
	if code := post(`{"phase":"load","flags":100003,"bt":"` + bt + `"}`); code != http.StatusOK {
		t.Fatalf("phase=load: %d", code)
	}
	var flags int
	if err := h.DB.QueryRowContext(context.Background(), `SELECT flags FROM unmask_event WHERE phase = 'load'`).Scan(&flags); err != nil {
		t.Fatal(err)
	}
	if flags != 100003&31 {
		t.Errorf("flags stored as %d, want the known bits of 100003 (%d)", flags, 100003&31)
	}
}
