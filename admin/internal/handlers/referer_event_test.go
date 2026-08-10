package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// refererForEvent feeds an untrusted header into the hunt event payload, so it
// must strip control chars (no log / JSON smuggling), cap the length, and be
// empty when absent (the common case -- omitempty keeps those rows unchanged).
func TestRefererForEvent(t *testing.T) {
	mk := func(v string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		if v != "" {
			r.Header.Set("Referer", v)
		}
		return r
	}

	if got := refererForEvent(mk("")); got != "" {
		t.Errorf("no Referer -> %q, want empty", got)
	}
	if got := refererForEvent(mk("  https://example.com/a?b=1  ")); got != "https://example.com/a?b=1" {
		t.Errorf("normal referer -> %q, want trimmed verbatim", got)
	}
	if got := refererForEvent(mk("https://e.com/x\r\nSet-Cookie: y\t")); strings.ContainsAny(got, "\r\n\t") {
		t.Errorf("control chars not stripped: %q", got)
	}
	long := "https://e.com/" + strings.Repeat("a", 400)
	if got := refererForEvent(mk(long)); len(got) != 300 {
		t.Errorf("referer not capped to 300: len=%d", len(got))
	}
}
