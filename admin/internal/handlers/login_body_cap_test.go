package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

// A login POST was read whole, up to 10 MB, and a failed one recorded the
// name it carried: a 3 MB name sat in the audit for good.  The body is now
// capped (loginBodyMax) -- past it the form reads empty and the page comes
// back -- and a long name under the cap is cut to the audit's column.
func TestLoginBodyIsCapped(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	withBasePath(h, "/unmask")
	post := func(name string) string {
		rr := httptest.NewRecorder()
		h.AdminLoginPost(rr, loginRequest(h, url.Values{"username": {name}, "password": {"x"}}))
		return rr.Header().Get("Location")
	}
	if loc := post(strings.Repeat("a", 3<<20)); !strings.Contains(loc, "err=expired") {
		t.Errorf("a 3 MB login was taken as a form: %q", loc)
	}
	post(strings.Repeat("b", 40<<10)) // under the cap: a failed login, recorded
	rows, err := h.UserRepo.ListAudit(t.Context(), 20, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, e := range rows {
		if n := utf8.RuneCountInString(e.Username); n > 64 {
			t.Errorf("an audit row carries a name of %d characters", n)
		}
		if e.Action == "login_failed" && strings.HasPrefix(e.Username, "bbb") {
			seen = true
		}
	}
	if !seen {
		t.Error("the failed login under the cap was not recorded")
	}
}
