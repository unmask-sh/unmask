package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The CSRF-backfill regression suite.  The scenario: a session cookie that has
// slid past its CSRF cookie's fixed 30-day life (the session refreshes on every
// request, the CSRF cookie only at login), so an authenticated GET arrives with
// a session but NO CSRF cookie.  The old code answered with a 303 to itself to
// "pick the cookie up" -- which has no terminating condition when the client
// does not return the cookie (Chrome withholds SameSite=Strict cookies for a
// whole cross-site-initiated redirect chain), and locked an operator out of
// /unmask/admin/ with ERR_TOO_MANY_REDIRECTS (web1-jp, 2026-07-10).

// backfillRequest runs one request with a valid session and no CSRF cookie
// through AuthMiddleware and returns the recorder plus the token the inner
// handler saw via CSRFTokenFromRequest.
func backfillRequest(t *testing.T, method, path string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	h, uid := reconfHandler(t, true)
	var seenToken string
	inner := func(w http.ResponseWriter, r *http.Request) {
		seenToken = CSRFTokenFromRequest(r)
		w.WriteHeader(http.StatusOK)
	}
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(superadminCookie(uid))
	rec := httptest.NewRecorder()
	h.AuthMiddleware(inner)(rec, req)
	return rec, seenToken
}

// TestCSRFBackfillRendersInsteadOfRedirecting: the backfilled GET must answer
// 200 with the page (no self-redirect), Set-Cookie the fresh token, and hand
// that SAME token to the handler so the rendered forms embed the value whose
// cookie is landing in this response.
func TestCSRFBackfillRendersInsteadOfRedirecting(t *testing.T) {
	rec, seenToken := backfillRequest(t, http.MethodGet, "/admin/")

	if rec.Code != http.StatusOK {
		t.Fatalf("backfilled GET must render, not redirect: got %d (Location=%q)",
			rec.Code, rec.Header().Get("Location"))
	}
	var issued *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			issued = c
		}
	}
	if issued == nil || issued.Value == "" {
		t.Fatal("backfilled GET must Set-Cookie the fresh CSRF token")
	}
	if seenToken == "" {
		t.Fatal("the handler must see the just-issued token via CSRFTokenFromRequest")
	}
	if seenToken != issued.Value {
		t.Errorf("rendered token and Set-Cookie value must match: form=%q cookie=%q", seenToken, issued.Value)
	}
}

// TestCSRFBackfillPostStill403s: a POST arriving without the CSRF cookie was
// rendered under an expired token, so it must keep failing closed (403), not
// be waved through with the just-minted one.
func TestCSRFBackfillPostStill403s(t *testing.T) {
	rec, _ := backfillRequest(t, http.MethodPost, "/admin/settings/save")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without a CSRF cookie must 403, got %d", rec.Code)
	}
}

// TestCSRFCookieSameSiteLax: the CSRF cookie must carry the SAME SameSite mode
// as the session cookie (Lax).  With Strict, Chrome omits the cookie from every
// hop of a cross-site-initiated redirect chain while still sending the Lax
// session cookie -- exactly the skew that fed the redirect loop.
func TestCSRFCookieSameSiteLax(t *testing.T) {
	if c := issueCSRFCookie("tok", true, true); c.SameSite != http.SameSiteLaxMode {
		t.Errorf("issueCSRFCookie SameSite = %v; want Lax (match the session cookie)", c.SameSite)
	}
	if c := clearCSRFCookie(true); c.SameSite != http.SameSiteLaxMode {
		t.Errorf("clearCSRFCookie SameSite = %v; want Lax", c.SameSite)
	}
	if s := issueSessionCookie("sec", 1, "admin", true, true); s.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite = %v; the CSRF cookie is documented to match it", s.SameSite)
	}
}

// TestCSRFTokenFromRequestPrefersCookie: when the request DOES carry the cookie,
// the context fallback must not shadow it -- verifyCSRF compares the submitted
// field against the client's live cookie value.
func TestCSRFTokenFromRequestPrefersCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "cookie-tok"})
	req = withIssuedCSRFToken(req, "issued-tok")
	if got := CSRFTokenFromRequest(req); got != "cookie-tok" {
		t.Errorf("cookie must win over the issued-token fallback, got %q", got)
	}

	bare := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	if got := CSRFTokenFromRequest(withIssuedCSRFToken(bare, "issued-tok")); got != "issued-tok" {
		t.Errorf("without a cookie the issued token must be used, got %q", got)
	}
	if got := CSRFTokenFromRequest(httptest.NewRequest(http.MethodGet, "/admin/", nil)); got != "" {
		t.Errorf("no cookie and no issued token must yield \"\", got %q", got)
	}
}

// TestCSRFBackfillLoopTermination replays the production failure shape: a
// client that NEVER returns the CSRF cookie (it strips Set-Cookie) re-requests
// the page.  Every response must be a renderable 200 -- the old behavior
// answered 303 forever until the browser gave up.
func TestCSRFBackfillLoopTermination(t *testing.T) {
	h, uid := reconfHandler(t, true)
	inner := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		req.AddCookie(superadminCookie(uid)) // session only; CSRF cookie dropped every time
		rec := httptest.NewRecorder()
		h.AuthMiddleware(inner)(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: a cookie-refusing client must still get the page (200), got %d", i+1, rec.Code)
		}
	}
}
