package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// A passed challenge leaves by stepping back to the entry the visitor arrived
// on, so the page they asked for keeps its referrer (challenge.js
// returnToArrival).  The server allows that only for a GET of a page whose
// original it knows: going back to a POST entry asks to resend the form, and
// a page with no original is a direct hit on the challenge or forward-auth,
// which is frozen.
func TestChallengeStepBackOnlyForAKnownGET(t *testing.T) {
	h := newTestHandler(t)
	for _, c := range []struct {
		name, method, target string
		want                 string
	}{
		{"a GET of a protected page", "GET", "/unmask/challenge/?_orig=%2Fnews%2F1%3Fp%3D2", "/*__STEP_BACK__*/1"},
		{"no original (forward-auth, a direct hit)", "GET", "/unmask/challenge/", "/*__STEP_BACK__*/0"},
		{"a POST", "POST", "/unmask/challenge/?_orig=%2Fform", "/*__STEP_BACK__*/0"},
	} {
		req := httptest.NewRequest(c.method, c.target, nil)
		req.Header.Set("Sec-Fetch-Dest", "document")
		w := httptest.NewRecorder()
		h.ServeChallenge(w, req)
		if body := w.Body.String(); !strings.Contains(body, c.want) {
			t.Errorf("%s: the page does not carry %s", c.name, c.want)
		}
	}
}

func TestBackRelayPage(t *testing.T) {
	h := newTestHandler(t)
	w := httptest.NewRecorder()
	h.ServeBackRelay(w, httptest.NewRequest("GET", "/unmask/static/back.html", nil))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	for k, want := range map[string]string{
		"Content-Type":  "text/html; charset=utf-8",
		"Cache-Control": "no-store",
	} {
		if got := w.Header().Get(k); got != want {
			t.Errorf("%s: %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(w.Header().Get("X-Robots-Tag"), "noindex") {
		t.Error("the relay must not be indexed")
	}
	if body := w.Body.String(); !strings.Contains(body, "history.back()") || !strings.Contains(body, "location.replace(to)") {
		t.Error("the relay must step back, and go to the page when it cannot")
	}
}

// The challenge page leaves its target in sessionStorage and the relay reads
// it back: the two must use one key, or the relay never steps back.
func TestStepBackKeySharedWithTheRelay(t *testing.T) {
	js, err := assets.Static.ReadFile("static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := assets.Static.ReadFile("static/back.html")
	if err != nil {
		t.Fatal(err)
	}
	const key = `'unmask_back'`
	if !strings.Contains(string(js), "var KEY = "+key) || !strings.Contains(string(relay), "getItem("+key+")") {
		t.Errorf("challenge.js and back.html must both use %s", key)
	}
	if !strings.Contains(string(js), "location.replace('/unmask/static/back.html')") {
		t.Error("challenge.js must step through the relay the daemon serves")
	}
}
