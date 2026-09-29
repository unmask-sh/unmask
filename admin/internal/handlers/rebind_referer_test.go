package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
)

// A silent rebind serves nothing, so its row is a session of one -- and the
// only row that can say where the visitor came from.  A serve records the
// Referer of the request it challenged; the rebind row stands where that serve
// would have been and records it the same way.  Without it a hunt view of the
// passes has a referer for every session but the rebound ones.
func TestRebindRowRecordsReferer(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
	const ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	const from = "https://github.com/unmask-sh/unmask"

	run := func(t *testing.T, referer string) map[string]any {
		t.Helper()
		h := newRebindTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/", nil)
		req.Host = "example.com"
		req.Header.Set("X-Real-IP", "203.0.113.5")
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Client-JA4", ja4)
		req.Header.Set("X-JA4-Verdict", "ok")
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		req.AddCookie(&http.Cookie{Name: "_bvj", Value: cookies.IssueJValue("test-secret",
			cookies.FingerprintHash(ja4), cookies.FingerprintHash(ua),
			"linrebind0000000000000000", 0, "example.com", "captcha")})
		if !h.tryRebind(httptest.NewRecorder(), req, "default", "bttest00.rebind") {
			t.Fatal("the rebind was refused; this test needs one that passes")
		}
		// The event is written off the request path; wait for it to land.
		var payload string
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := h.DB.QueryRow(`SELECT payload_json FROM unmask_event WHERE phase = 'bv_rebind'`).Scan(&payload)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no bv_rebind row was written: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		var p map[string]any
		if err := json.Unmarshal([]byte(payload), &p); err != nil {
			t.Fatalf("payload %q: %v", payload, err)
		}
		return p
	}

	t.Run("a referer is recorded", func(t *testing.T) {
		p := run(t, from)
		if p["referer"] != from {
			t.Errorf("payload referer = %v, want %q", p["referer"], from)
		}
		if p["bt"] != "bttest00.rebind" {
			t.Errorf("payload bt = %v; the row must stay attributable to its request", p["bt"])
		}
	})
	t.Run("none sent, none recorded", func(t *testing.T) {
		p := run(t, "")
		if _, has := p["referer"]; has {
			t.Errorf("payload carries referer %v for a request that sent none", p["referer"])
		}
	})
}
