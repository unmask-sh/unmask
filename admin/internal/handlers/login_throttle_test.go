package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The credential endpoints carry their own per-IP guard now, because the
// rate-limit zone that used to stand in front of them never fired: the
// protected path hands every client that can reach the login POST a _bv
// cookie, and challenge-mode zones exempt _bv holders from counting.  A
// handler-side counter has no cookie to be exempted by -- these tests drive
// the counter itself; the handler wiring is covered below.
func TestLoginThrottleLocksAfterRepeatedFailures(t *testing.T) {
	tr := newLoginThrottle()
	now := time.Unix(1_800_000_000, 0)

	for i := 0; i < tr.failLimit-1; i++ {
		if d := tr.note(loginKey("203.0.113.7"), now, tr.failLimit, tr.failWindow, tr.lockFor); d != 0 {
			t.Fatalf("failure %d already locked", i+1)
		}
	}
	if d := tr.note(loginKey("203.0.113.7"), now, tr.failLimit, tr.failWindow, tr.lockFor); d != tr.lockFor {
		t.Fatalf("failure %d should trip the lock for %v, got %v", tr.failLimit, tr.lockFor, d)
	}
	if d := tr.lockedFor(loginKey("203.0.113.7"), now.Add(time.Minute)); d <= 0 {
		t.Error("the address should still be locked a minute in")
	}
	// Another address is untouched -- the scope is per-IP by design (a
	// per-account lockout would let an attacker lock the operator out).
	if d := tr.lockedFor(loginKey("198.51.100.9"), now); d != 0 {
		t.Error("an unrelated address got locked")
	}
	// The lock expires on its own.
	if d := tr.lockedFor(loginKey("203.0.113.7"), now.Add(tr.lockFor+time.Second)); d != 0 {
		t.Error("the lock outlived its duration")
	}
}

func TestLoginThrottleWindowAndReset(t *testing.T) {
	tr := newLoginThrottle()
	now := time.Unix(1_800_000_000, 0)

	// Failures older than the window age out: N-1 stale failures plus one
	// fresh one must not lock.
	for i := 0; i < tr.failLimit-1; i++ {
		tr.note(loginKey("a"), now, tr.failLimit, tr.failWindow, tr.lockFor)
	}
	later := now.Add(tr.failWindow + time.Second)
	if d := tr.note(loginKey("a"), later, tr.failLimit, tr.failWindow, tr.lockFor); d != 0 {
		t.Error("stale failures still counted toward the lock")
	}

	// A successful login clears the slate mid-streak.
	for i := 0; i < tr.failLimit-1; i++ {
		tr.note(loginKey("b"), now, tr.failLimit, tr.failWindow, tr.lockFor)
	}
	tr.clear(loginKey("b"))
	if d := tr.note(loginKey("b"), now, tr.failLimit, tr.failWindow, tr.lockFor); d != 0 {
		t.Error("a successful login did not reset the failure count")
	}
}

// End-to-end through the handler: the eleventh bad password from one address
// answers 429 with Retry-After, and the login page is no longer consulted.
func TestLoginPostLocksTheHammeringAddress(t *testing.T) {
	h := newTestHandler(t)
	post := func() *httptest.ResponseRecorder {
		form := url.Values{"username": {"admin"}, "password": {"wrong"}}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:44321"
		rr := httptest.NewRecorder()
		h.AdminLoginPost(rr, req)
		return rr
	}
	tr := h.throttle()
	for i := 0; i < tr.failLimit-1; i++ {
		if rr := post(); rr.Code != http.StatusFound {
			t.Fatalf("failure %d: want the invalid-login redirect, got %d", i+1, rr.Code)
		}
	}
	rr := post()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("failure %d should answer 429, got %d", tr.failLimit, rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After gives the client nothing to schedule by")
	}
	// And it holds on the next attempt, before any credential check runs.
	if rr := post(); rr.Code != http.StatusTooManyRequests {
		t.Errorf("locked address answered %d, want 429", rr.Code)
	}
}

// The forgot-password cap counts REQUESTS -- each accepted one sends mail and
// mints a token, so there is no "failure" to wait for.
func TestForgotPasswordCapsRequestsPerAddress(t *testing.T) {
	tr := newLoginThrottle()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < tr.forgotLimit-1; i++ {
		if d := tr.note(forgotKey("x"), now, tr.forgotLimit, tr.forgotWindow, tr.forgotWindow); d != 0 {
			t.Fatalf("request %d already capped", i+1)
		}
	}
	if d := tr.note(forgotKey("x"), now, tr.forgotLimit, tr.forgotWindow, tr.forgotWindow); d == 0 {
		t.Fatal("the cap never tripped")
	}
	// The two axes are namespaced: burning the forgot cap must not have
	// touched the same address's login state.
	if d := tr.note(loginKey("x"), now, tr.failLimit, tr.failWindow, tr.lockFor); d != 0 {
		t.Error("forgot-password requests leaked into the login-failure count")
	}
}
