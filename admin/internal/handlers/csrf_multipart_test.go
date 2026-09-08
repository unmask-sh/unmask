package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

// multipartPost builds a multipart/form-data POST to path carrying the given
// fields, the way a browser submits an upload form.
func multipartPost(t *testing.T, path string, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// A multipart form whose token rides only in the body (no header, no query
// mirror) still verifies: the branding tab's per-site "reset to default"
// button posts to its own formaction, which the shim did not decorate, and
// every such click was refused as a csrf mismatch (0.1.25..0.1.40).
func TestVerifyCSRF_MultipartBodyField(t *testing.T) {
	const tok = "tok-multipart-1"
	req := multipartPost(t, "/unmask/admin/settings/branding/site/delete?site=shop.example.com", map[string]string{"_csrf": tok, "site": "shop.example.com"})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
	// The middleware runs ParseForm before verifyCSRF; for multipart that
	// reads nothing from the body -- exactly the state the fallback must cope with.
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if !verifyCSRF(req) {
		t.Fatal("a token carried only in the multipart body must verify")
	}
	// The upload handler's own parse afterwards must still see the fields.
	if err := req.ParseMultipartForm(4 << 20); err != nil {
		t.Fatalf("second ParseMultipartForm: %v", err)
	}
	if got := req.FormValue("site"); got != "shop.example.com" {
		t.Errorf("form values must survive the verify-time parse, got site=%q", got)
	}

	wrong := multipartPost(t, "/unmask/admin/settings/branding/site/delete?site=shop.example.com", map[string]string{"_csrf": "other"})
	wrong.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
	_ = wrong.ParseForm()
	if verifyCSRF(wrong) {
		t.Fatal("a body token that does not match the cookie must not verify")
	}
	none := multipartPost(t, "/unmask/admin/settings/branding/site/delete?site=shop.example.com", map[string]string{"site": "shop.example.com"})
	none.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
	_ = none.ParseForm()
	if verifyCSRF(none) {
		t.Fatal("a multipart body without the field must not verify")
	}
}
