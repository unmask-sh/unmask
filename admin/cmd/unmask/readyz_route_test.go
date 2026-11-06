package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// healthz stays what it was on a daemon that has its database, and readyz
// says 200 there.
func TestHealthzAndReadyzWithADatabase(t *testing.T) {
	s, _, mux := routeFixture(t)
	for path, want := range map[string]string{"/healthz": "ok\n", "/readyz": "ok\n"} {
		rec := serve(mux, httptest.NewRequest(http.MethodGet, s.Server.BasePath+path, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != want {
			t.Errorf("GET %s: %d %q, want 200 %q", path, rec.Code, rec.Body.String(), want)
		}
	}
}
