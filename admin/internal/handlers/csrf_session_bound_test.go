package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The CSRF token is derived from the session cookie's signature under a key
// of its own: one token per session, another secret another token, and a
// value with no signature part has none.
func TestCSRFTokenDerivedFromSession(t *testing.T) {
	const secret = "test-secret"
	a := issueSessionCookie(secret, "/unmask", 1, user.RoleAdmin, false, false, 0)
	b := issueSessionCookie(secret, "/unmask", 2, user.RoleAdmin, false, false, 0)
	ta, tb := csrfTokenFor(secret, a.Value), csrfTokenFor(secret, b.Value)
	if len(ta) != 64 || ta == tb {
		t.Fatalf("tokens: %q / %q", ta, tb)
	}
	if ta != csrfTokenFor(secret, a.Value) {
		t.Error("the token of a session is not stable")
	}
	if csrfTokenFor("other-secret", a.Value) == ta {
		t.Error("the token does not depend on the secret")
	}
	if got := csrfTokenFor(secret, "no-signature"); got != "" {
		t.Errorf("a value with no signature part has a token: %q", got)
	}
}

// csrfPost is a url-encoded POST carrying the cookies given and tok in the
// _csrf field.
func csrfPost(path string, cookies []*http.Cookie, tok string) *http.Request {
	form := url.Values{}
	if tok != "" {
		form.Set(csrfFieldName, tok)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	_ = req.ParseForm()
	return req
}

// verifyCSRF takes the token of the session cookie the request carries and
// nothing else: another session's token is refused, and so is the
// double-submit forgery -- a CSRF cookie planted from a sibling host with
// the same value in the field -- since the cookie is not read.
func TestVerifyCSRFTakesOnlyTheSessionsToken(t *testing.T) {
	const secret = "test-secret"
	victim := issueSessionCookie(secret, "/unmask", 1, user.RoleAdmin, false, false, 0)
	other := issueSessionCookie(secret, "/unmask", 2, user.RoleAdmin, false, false, 0)
	tok := csrfTokenFor(secret, victim.Value)
	cookie := func(v string) *http.Cookie { return &http.Cookie{Name: csrfCookieName, Value: v} }

	if !verifyCSRF(secret, csrfPost("/admin/settings/save", []*http.Cookie{victim, cookie(tok)}, tok)) {
		t.Error("the session's own token, with its cookie, is refused")
	}
	if !verifyCSRF(secret, csrfPost("/admin/settings/save", []*http.Cookie{victim}, tok)) {
		t.Error("the session's own token without the cookie is refused: the cookie must have no say")
	}
	hdr := csrfPost("/admin/api/x", []*http.Cookie{victim}, "")
	hdr.Header.Set(csrfHeaderName, tok)
	if !verifyCSRF(secret, hdr) {
		t.Error("the token in the X-CSRF-Token header is refused")
	}
	if verifyCSRF(secret, csrfPost("/admin/settings/save", []*http.Cookie{victim}, csrfTokenFor(secret, other.Value))) {
		t.Error("another session's token passed")
	}
	planted := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if verifyCSRF(secret, csrfPost("/admin/settings/save", []*http.Cookie{victim, cookie(planted)}, planted)) {
		t.Error("a planted cookie with the same value in the field passed (the double-submit forgery)")
	}
	if verifyCSRF(secret, csrfPost("/admin/settings/save", []*http.Cookie{cookie(tok)}, tok)) {
		t.Error("a request with no session passed")
	}
	if verifyCSRF(secret, csrfPost("/admin/settings/save", []*http.Cookie{victim}, "")) {
		t.Error("a request with no token passed")
	}
	if verifyCSRF("rotated-secret", csrfPost("/admin/settings/save", []*http.Cookie{victim}, tok)) {
		t.Error("a token from before the secret was rotated passed")
	}
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	var out *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			out = c
		}
	}
	return out
}

// AuthMiddleware derives the token for the session the request carries,
// hands it to the page, and (re)issues the JS-readable cookie only when the
// request's does not hold it; a POST passes with that token and with no
// other.
func TestAuthMiddlewareIssuesTheSessionsToken(t *testing.T) {
	h, uid := reconfHandler(t, true)
	withBasePath(h, "/unmask")
	session := superadminCookie(uid)
	tok := csrfTokenFor("test-secret", session.Value)

	var seen string
	called := false
	inner := func(w http.ResponseWriter, r *http.Request) {
		called = true
		seen = CSRFTokenFromRequest(r)
	}
	get := func(csrf *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		req.AddCookie(session)
		if csrf != nil {
			req.AddCookie(csrf)
		}
		rec := httptest.NewRecorder()
		h.AuthMiddleware(inner)(rec, req)
		return rec
	}

	rec := get(nil)
	if rec.Code != http.StatusOK || seen != tok {
		t.Fatalf("GET without the cookie: code=%d token=%q want %q", rec.Code, seen, tok)
	}
	if c := cookieNamed(rec, csrfCookieName); c == nil || c.Value != tok || c.Path != "/unmask" {
		t.Fatalf("the issued CSRF cookie: %+v", c)
	}
	rec = get(&http.Cookie{Name: csrfCookieName, Value: tok})
	if c := cookieNamed(rec, csrfCookieName); c != nil {
		t.Errorf("a request holding the token had the cookie set again: %+v", c)
	}
	rec = get(&http.Cookie{Name: csrfCookieName, Value: "stale"})
	if c := cookieNamed(rec, csrfCookieName); c == nil || c.Value != tok {
		t.Errorf("a stale cookie was not replaced: %+v", c)
	}

	called = false
	rec = httptest.NewRecorder()
	h.AuthMiddleware(inner)(rec, csrfPost("/admin/settings/save", []*http.Cookie{session}, tok))
	if rec.Code != http.StatusOK || !called {
		t.Errorf("a POST with the session's token: code=%d called=%v", rec.Code, called)
	}
	called = false
	rec = httptest.NewRecorder()
	otherTok := csrfTokenFor("test-secret", issueSessionCookie("test-secret", "/unmask", uid+1, user.RoleAdmin, false, false, 0).Value)
	h.AuthMiddleware(inner)(rec, csrfPost("/admin/settings/save", []*http.Cookie{session, {Name: csrfCookieName, Value: otherTok}}, otherTok))
	if rec.Code != http.StatusForbidden || called {
		t.Errorf("a POST with another session's token (and a matching cookie): code=%d called=%v", rec.Code, called)
	}
}

// withBasePath gives h's settings a base path, as a native install has.
func withBasePath(h *Handler, base string) {
	s := h.snapshotSettings()
	s.Server.BasePath = base
	h.SetSettings(s)
}

// The admin's cookies live on the base path, not on /: the protected site
// shares the origin, and a cookie on / went to the upstream application
// with every request, while everything under the base path is the daemon's
// own.  Login issues both there, the middleware clears a refused session
// there, and logout clears both paths -- the base path and /, where they
// lived before.
func TestAdminCookiesScopedToBasePath(t *testing.T) {
	if got := adminCookiePath("/unmask"); got != "/unmask" {
		t.Fatalf("adminCookiePath = %q", got)
	}
	if got := adminCookiePath(""); got != "/" {
		t.Fatalf("adminCookiePath(\"\") = %q", got)
	}
	for _, c := range []*http.Cookie{
		issueSessionCookie("s", "/unmask", 1, user.RoleAdmin, true, false, 0),
		clearSessionCookie("/unmask", true),
		issueCSRFCookie("tok", "/unmask", true, false),
		clearCSRFCookie("/unmask", true),
	} {
		if c.Path != "/unmask" {
			t.Errorf("%s: Path = %q", c.Name, c.Path)
		}
	}

	h, _ := reconfHandler(t, true)
	withBasePath(h, "/unmask")
	form := url.Values{"username": {"admin"}, "password": {"correct-horse-battery"}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.AdminLoginPost(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	session, csrf := cookieNamed(rec, sessionCookieName), cookieNamed(rec, csrfCookieName)
	if session == nil || session.Path != "/unmask" || !session.HttpOnly {
		t.Fatalf("the session cookie login set: %+v", session)
	}
	if csrf == nil || csrf.Path != "/unmask" || csrf.Value != csrfTokenFor("test-secret", session.Value) {
		t.Fatalf("the CSRF cookie login set: %+v", csrf)
	}

	// A session the middleware refuses is cleared on the same path.
	gone := issueSessionCookie("test-secret", "/unmask", 999, user.RoleAdmin, false, false, 0)
	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req.AddCookie(gone)
	rec = httptest.NewRecorder()
	h.AuthMiddleware(func(http.ResponseWriter, *http.Request) { t.Error("a session of no account reached the handler") })(rec, req)
	if c := cookieNamed(rec, sessionCookieName); c == nil || c.MaxAge != -1 || c.Path != "/unmask" {
		t.Errorf("the refused session's clear: %+v", c)
	}
}

// Logout ends every session of the account: the generation moves on, so the
// cookie the browser was told to drop -- and any copy of it, on any device
// -- is refused from then on.  The clear reaches the admin path and /.
func TestLogoutEndsTheAccountsSessions(t *testing.T) {
	h, uid := reconfHandler(t, true)
	withBasePath(h, "/unmask")
	session := superadminCookie(uid)
	tok := csrfTokenFor("test-secret", session.Value)
	logout := h.AdminIPAllowMiddleware(h.RequireCSRFFunc(h.AdminLogout))

	called := false
	page := h.AuthMiddleware(func(http.ResponseWriter, *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req.AddCookie(session)
	page(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("the session must pass before the logout")
	}

	rec := httptest.NewRecorder()
	logout(rec, csrfPost("/unmask/admin/logout", []*http.Cookie{session}, "not-the-token"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a logout without the session's token (a forced logout from another site): %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	logout(rec, csrfPost("/unmask/admin/logout", []*http.Cookie{session}, tok))
	if rec.Code != http.StatusFound || !strings.HasSuffix(rec.Header().Get("Location"), "/unmask/admin/login") {
		t.Fatalf("logout: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	paths := map[string]map[string]bool{}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge != -1 {
			t.Errorf("logout set a cookie that is not a clear: %+v", c)
		}
		if paths[c.Name] == nil {
			paths[c.Name] = map[string]bool{}
		}
		paths[c.Name][c.Path] = true
	}
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		if !paths[name]["/unmask"] || !paths[name]["/"] {
			t.Errorf("%s is not cleared on both /unmask and /: %v", name, paths[name])
		}
	}

	called = false
	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	req.AddCookie(session)
	rec = httptest.NewRecorder()
	page(rec, req)
	if called || rec.Code != http.StatusFound {
		t.Errorf("the session is still good after the logout: called=%v code=%d", called, rec.Code)
	}
	u, err := h.UserRepo.GetByID(req.Context(), uid)
	if err != nil || u.SessionGen != 1 {
		t.Errorf("session_gen after the logout: %d (%v)", u.SessionGen, err)
	}
}

// AuthMiddleware reads admin_allowed_hosts as the login gate does: a session
// under a name outside the list is refused.
func TestAuthMiddlewareChecksAllowedHosts(t *testing.T) {
	h, uid := reconfHandler(t, true)
	s := h.snapshotSettings()
	s.Nginx.AdminAllowedHosts = []string{"exact:admin.example.com"}
	h.SetSettings(s)
	for host, want := range map[string]int{"other.example.com": http.StatusForbidden, "admin.example.com": http.StatusOK} {
		req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		req.Host = host
		req.AddCookie(superadminCookie(uid))
		rec := httptest.NewRecorder()
		h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(rec, req)
		if rec.Code != want {
			t.Errorf("Host %s: %d, want %d (%s)", host, rec.Code, want, strings.TrimSpace(rec.Body.String()))
		}
	}
}
