package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The route the admin's Content-Security-Policy reports to takes the
// browser's post as the browser sends it: with no session (the login page
// reports too) and no CSRF token (the browser has none to send).  The auth
// walk lists it among the routes without a session for that reason
// (adminRoutesWithoutSession); this is the other half -- that it answers.
func TestCSPReportRouteNeedsNoSessionAndNoToken(t *testing.T) {
	s, _, mux := routeFixture(t)
	body := `{"csp-report":{"document-uri":"http://admin.test/unmask/admin/login","effective-directive":"script-src-elem","blocked-uri":"inline","line-number":3}}`
	req := httptest.NewRequest(http.MethodPost, s.Server.BasePath+"/admin/csp-report", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/csp-report")
	if rec := serve(mux, req); rec.Code != http.StatusNoContent {
		t.Errorf("a report with no cookie at all: %d %s, want 204", rec.Code, rec.Body.String())
	}
	// GET is not a route: nothing to read there.
	if rec := serve(mux, httptest.NewRequest(http.MethodGet, s.Server.BasePath+"/admin/csp-report", nil)); rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
		t.Errorf("GET on the report route answered %d", rec.Code)
	}
}
