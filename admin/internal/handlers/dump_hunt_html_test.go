package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// Not a test: a way to get the REAL hunt page out for browser measurement.
// Enabled only when UNMASK_DUMP_HUNT points at a file, so `go test ./...`
// ignores it.
func TestDumpHuntHTMLForMeasurement(t *testing.T) {
	out := os.Getenv("UNMASK_DUMP_HUNT")
	if out == "" {
		t.Skip("set UNMASK_DUMP_HUNT=<path> to dump the hunt page")
	}
	h := newTestHandler(t)
	const longUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"
	seed := []struct{ phase, payload, ua string }{
		{"bv_rebind_reject", `{"bt":"s1","reason":"bvj_invalid"}`, longUA},
		{"serve", `{"bt":"s1","force_reason":"none","orig_path":"/article/detail/12345/"}`, longUA},
		{"load", `{"bt":"s1"}`, longUA},
		{"captcha", `{"bt":"s1"}`, longUA},
		{"bv_pow_then_captcha", `{"bt":"s1"}`, longUA},
		{"serve", `{"bt":"s2","force_reason":"none","orig_path":"/news/detail/999/"}`, longUA},
		{"load", `{"bt":"s2"}`, longUA},
		{"bv_pow_only", `{"bt":"s2"}`, longUA},
	}
	for _, s := range seed {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','https',443,x'7f000001',?,'t13d1516h2_8daaf6152771_d8a2da3f94cd','ok',0,?,0,0,'','',?,datetime('now'))`,
			s.ua, s.phase, s.payload); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt: %d", rr.Code)
	}
	if err := os.WriteFile(out, rr.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d bytes to %s", rr.Body.Len(), out)
}
