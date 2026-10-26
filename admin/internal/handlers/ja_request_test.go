package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
)

// jaRequest is httptest.NewRequest with the page asked for in Japanese.
// The tests that use it were written against the Japanese copy while it
// was what a request naming no language got; since 0.1.53 such a request
// is served in English (i18n.Resolve), so they say which they expect.  A
// language cookie set on the request afterwards still wins, as it does for
// a visitor.
func jaRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.Header.Set("Accept-Language", "ja")
	return r
}
