package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// loginRequest builds a sign-in POST the way the form sends it: with the
// nonce cookie the form's GET set, and the token derived from it in _csrf.
func loginRequest(h *Handler, form url.Values) *http.Request {
	const nonce = "0123456789abcdef0123456789abcdef"
	form = cloneValues(form)
	form.Set(csrfFieldName, loginCSRFToken(h.cfg().Secret.BVSecret, nonce))
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: loginCSRFCookieName, Value: nonce})
	return req
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// A sign-in POST that does not come from the form -- no token, a token
// without its cookie, or a token for another nonce -- is answered with the
// form again, and no session is issued.  Until 0.1.54 the POST was exempt
// from the CSRF check, so a page on another origin could sign a visitor
// into an account of its choosing.
func TestLoginPostNeedsTheFormsToken(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	withBasePath(h, "/unmask")
	if _, err := h.UserRepo.CreateWithProfile(t.Context(), "carol", "test-password-carol", "superadmin", "", false); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"username": {"carol"}, "password": {"test-password-carol"}}
	secret := h.cfg().Secret.BVSecret
	const nonce = "0123456789abcdef0123456789abcdef"
	good := loginCSRFToken(secret, nonce)

	cases := []struct {
		name   string
		cookie string
		token  string
	}{
		{"no token, no cookie", "", ""},
		{"no token", nonce, ""},
		{"token without its cookie", "", good},
		{"token for another nonce", "fedcba9876543210fedcba9876543210", good},
		{"a cookie that is not a nonce", "not-a-nonce", loginCSRFToken(secret, "not-a-nonce")},
	}
	for _, c := range cases {
		f := cloneValues(form)
		if c.token != "" {
			f.Set(csrfFieldName, c.token)
		}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/login", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if c.cookie != "" {
			req.AddCookie(&http.Cookie{Name: loginCSRFCookieName, Value: c.cookie})
		}
		rr := httptest.NewRecorder()
		h.AdminLoginPost(rr, req)
		loc := rr.Header().Get("Location")
		if rr.Code != http.StatusFound || !strings.Contains(loc, "/admin/login?err=expired") {
			t.Errorf("%s: want the form again (302 to login?err=expired), got %d %s", c.name, rr.Code, loc)
		}
		for _, ck := range rr.Result().Cookies() {
			if ck.Name == sessionCookieName && ck.Value != "" {
				t.Errorf("%s: a session was issued", c.name)
			}
		}
	}

	// The form's own POST signs in.
	rr := httptest.NewRecorder()
	h.AdminLoginPost(rr, loginRequest(h, form))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/unmask/admin/" {
		t.Fatalf("the form's POST: want 302 to /unmask/admin/, got %d %s", rr.Code, rr.Header().Get("Location"))
	}
	var session bool
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == sessionCookieName && ck.Value != "" {
			session = true
		}
	}
	if !session {
		t.Error("the form's POST issued no session")
	}
}

// The form's GET sets the nonce cookie and embeds the token derived from
// it; a GET that brings a nonce keeps it, so two sign-in tabs do not
// invalidate each other.
func TestLoginGetIssuesNonceAndToken(t *testing.T) {
	h := newTestHandler(t)
	withBasePath(h, "/unmask")
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil)
	rr := httptest.NewRecorder()
	h.AdminLoginGet(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET login: %d", rr.Code)
	}
	var nonce string
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == loginCSRFCookieName {
			nonce = ck.Value
			if !ck.HttpOnly || ck.Path != adminCookiePath("/unmask") || ck.MaxAge <= 0 {
				t.Errorf("nonce cookie: want HttpOnly, on the admin path, with a lifetime; got %+v", ck)
			}
		}
	}
	if !validLoginNonce(nonce) {
		t.Fatalf("GET login set no usable nonce cookie: %q", nonce)
	}
	want := `name="_csrf" value="` + loginCSRFToken(h.cfg().Secret.BVSecret, nonce) + `"`
	if !strings.Contains(rr.Body.String(), want) {
		t.Errorf("the form does not carry the token of its nonce")
	}

	// A second GET with the nonce keeps it and sets no new one.
	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/login", nil)
	req.AddCookie(&http.Cookie{Name: loginCSRFCookieName, Value: nonce})
	rr = httptest.NewRecorder()
	h.AdminLoginGet(rr, req)
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == loginCSRFCookieName {
			t.Errorf("a GET that brought a nonce set another: %s", ck.Value)
		}
	}
	if !strings.Contains(rr.Body.String(), want) {
		t.Errorf("the second form does not carry the same token")
	}
}
