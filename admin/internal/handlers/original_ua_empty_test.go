package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEmptyOriginalUAIsNotTheFetchersUA: a visitor that sends no User-Agent is
// one of the strongest bot tells there is, and the forward-auth protocol
// reports that as an X-Original-UA the proxy set to the empty string.  Falling
// through to this request's own User-Agent replaced that fact with the
// identity of whatever made the subrequest: under Apache/mod_lua that is
// luasocket, so on a live install 60% of all events were recorded as
// "LuaSocket 3.0.0" -- and classified as that rather than as UA-less.  nginx's
// auth_request inherits the client's headers, which is why the substitution
// stayed invisible until unmask ran behind Apache.
func TestEmptyOriginalUAIsNotTheFetchersUA(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
	r.Header.Set("X-Original-UA", "") // proxy says: the visitor sent none
	r.Header.Set("User-Agent", "LuaSocket 3.0.0")

	if got := headerOrFallback(r, "X-Original-UA", r.Header.Get("User-Agent")); got != "" {
		t.Errorf("UA = %q, want empty -- the visitor's silence, not the fetcher's name", got)
	}
}

// TestOriginalUAWinsWhenPresent: the ordinary case still resolves to the
// visitor's own UA.
func TestOriginalUAWinsWhenPresent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
	r.Header.Set("X-Original-UA", "Mozilla/5.0 (Windows NT 10.0) Chrome/150")
	r.Header.Set("User-Agent", "LuaSocket 3.0.0")

	got := headerOrFallback(r, "X-Original-UA", r.Header.Get("User-Agent"))
	if got != "Mozilla/5.0 (Windows NT 10.0) Chrome/150" {
		t.Errorf("UA = %q, want the visitor's", got)
	}
}

// TestAbsentHeaderStillFallsBack: a caller that does not speak the
// X-Original-* protocol at all (a direct hit on /api/check) has told us
// nothing, so the request's own UA is still the best available answer.
func TestAbsentHeaderStillFallsBack(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
	r.Header.Set("User-Agent", "curl/8.0")

	if got := headerOrFallback(r, "X-Original-UA", r.Header.Get("User-Agent")); got != "curl/8.0" {
		t.Errorf("UA = %q, want the fallback for a caller that set no header", got)
	}
}

// TestWhitespaceOnlyCountsAsEmpty: a proxy that forwards " " has still told us
// the visitor sent nothing usable.
func TestWhitespaceOnlyCountsAsEmpty(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
	r.Header.Set("X-Original-UA", "   ")
	r.Header.Set("User-Agent", "LuaSocket 3.0.0")

	if got := headerOrFallback(r, "X-Original-UA", r.Header.Get("User-Agent")); got != "" {
		t.Errorf("UA = %q, want empty", got)
	}
}

// TestSecondaryHeaderStillHonoured: X-Original-User-Agent is the older spelling
// and remains a valid fallback for a proxy that sets only that one.
func TestSecondaryHeaderStillHonoured(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
	r.Header.Set("X-Original-User-Agent", "Mozilla/5.0 (X11; Linux) Firefox/150")
	r.Header.Set("User-Agent", "LuaSocket 3.0.0")

	got := headerOrFallback(r, "X-Original-UA",
		r.Header.Get("X-Original-User-Agent"), r.Header.Get("User-Agent"))
	if got != "Mozilla/5.0 (X11; Linux) Firefox/150" {
		t.Errorf("UA = %q, want the X-Original-User-Agent value", got)
	}
}
