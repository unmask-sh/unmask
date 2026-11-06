package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The forward-auth decision handler acts on the X-Original-* headers of its
// caller, so the fronts keep visitors off it by naming its path (an exact
// 404 in nginx, a ProxyPass exclusion in Apache).  That only holds while the
// handler has the one path they name: /api/{site}/check was a second one,
// which every front proxied through with the visitor's own headers.

func TestAuthCheckIsRegisteredOnOnePath(t *testing.T) {
	s, _, mux := routeFixture(t)
	base := s.Server.BasePath
	var got []string
	for _, p := range routePatterns(t, mux) {
		if strings.HasSuffix(p, "/check") {
			got = append(got, p)
		}
	}
	want := []string{"GET " + base + "/api/check", "POST " + base + "/api/check"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("routes ending in /check:\n  %s\nwant only:\n  %s\n(a second path to AuthCheck is one the fronts do not block)",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestAuthCheckAliasIsGone(t *testing.T) {
	s, h, mux := routeFixture(t)
	base := s.Server.BasePath
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, path := range []string{"/api/default/check", "/api/x/check", "/api/check/", "/api/check/x"} {
			req := httptest.NewRequest(method, base+path, nil)
			req.Header.Set("X-Original-IP", "203.0.113.222")
			req.Header.Set("X-Original-URI", "/wp-login.php")
			req.Header.Set("X-Original-Host", "www.example.com")
			if rec := serve(mux, req); rec.Code != http.StatusNotFound {
				t.Errorf("%s %s: got %d, want 404", method, path, rec.Code)
			}
		}
	}
	// Nothing above reached the handler: the fixture starts without a ban,
	// and the address the headers named did not get one.
	var n int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM unmask_ban`).Scan(&n); err != nil {
		t.Fatalf("count bans: %v", err)
	}
	if n != 0 {
		t.Fatalf("a request to a path that is not the decision endpoint left %d ban(s)", n)
	}
}
