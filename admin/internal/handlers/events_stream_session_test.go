package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// streamThroughMiddleware opens the live-tail stream the way the page does
// -- through AuthMiddleware, with the session cookie c -- and returns a
// channel that is closed when the handler returns, and the context that
// stands for the page staying open (until cancel or the deadline).
func streamThroughMiddleware(t *testing.T, h *Handler, c *http.Cookie, open time.Duration) (done chan struct{}, ctx context.Context, rr *httptest.ResponseRecorder, reached *bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), open)
	t.Cleanup(cancel)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/api/events/stream", nil).WithContext(ctx)
	req.AddCookie(c)
	rr = httptest.NewRecorder()
	reached = new(bool)
	mw := h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		h.AdminEventsStream(w, r)
	})
	done = make(chan struct{})
	go func() {
		defer close(done)
		mw(rr, req)
	}()
	return done, ctx, rr, reached
}

// An open live tail is one request that lasts as long as its page.  The
// middleware checked its session when it opened, and nothing after: signing
// out (or a password change, a suspension) ended every other request of the
// session, and the stream kept sending visitors' addresses to the tab.  The
// stream now checks the session again while it is open and ends with it.
func TestEventsStreamEndsWithItsSession(t *testing.T) {
	orig := streamSessionEvery
	streamSessionEvery = 100 * time.Millisecond
	t.Cleanup(func() { streamSessionEvery = orig })

	h := sessionGenHandler(t)
	bg := context.Background()
	eve, err := h.UserRepo.CreateWithProfile(bg, "eve", "test-password-eve1", "viewer", "", false)
	if err != nil {
		t.Fatal(err)
	}
	c := issueSessionCookie(h.adminSecret(), "/unmask", eve.ID, eve.Role, false, false, eve.SessionGen)

	done, ctx, rr, reached := streamThroughMiddleware(t, h, c, 10*time.Second)
	// Several checks pass while the session stands.
	select {
	case <-done:
		t.Fatalf("the stream ended while its session stood (reached=%v code=%d)", *reached, rr.Code)
	case <-time.After(500 * time.Millisecond):
	}

	// What signing out does to the account (AdminLogout).
	if err := h.UserRepo.BumpSessionGen(bg, eve.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream was still open 3s after its session ended")
	}
	if !*reached {
		t.Fatal("the stream never opened")
	}
	if ctx.Err() != nil {
		t.Fatal("the stream ended only because the page went away")
	}
}

// A suspended account's stream ends too, and a stream whose session stands
// stays open until its page goes away.
func TestEventsStreamSessionChecks(t *testing.T) {
	orig := streamSessionEvery
	streamSessionEvery = 100 * time.Millisecond
	t.Cleanup(func() { streamSessionEvery = orig })

	h := sessionGenHandler(t)
	bg := context.Background()
	bob, err := h.UserRepo.CreateWithProfile(bg, "bob", "test-password-bob1", "admin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	c := issueSessionCookie(h.adminSecret(), "/unmask", bob.ID, bob.Role, false, false, bob.SessionGen)

	// Standing: open for the whole of its page's life.
	done, ctx, _, reached := streamThroughMiddleware(t, h, c, 800*time.Millisecond)
	<-done
	if !*reached || ctx.Err() == nil {
		t.Fatalf("a stream whose session stands ended before its page went away (reached=%v)", *reached)
	}

	// Suspended while open.
	done, ctx, _, _ = streamThroughMiddleware(t, h, c, 10*time.Second)
	time.Sleep(300 * time.Millisecond)
	if err := h.UserRepo.SetDisabled(bg, bob.ID, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream of a suspended account was still open 3s later")
	}
	if ctx.Err() != nil {
		t.Fatal("the stream ended only because the page went away")
	}
}

// The payload the middleware put on the request is the stream's to read,
// not to change: sessionAccount writes the current role into what it is
// given, so the check works on a copy.
func TestStreamSessionStandsLeavesTheRequestsPayload(t *testing.T) {
	h := sessionGenHandler(t)
	bg := context.Background()
	carol, err := h.UserRepo.CreateWithProfile(bg, "carol", "test-password-carol", "admin", "", false)
	if err != nil {
		t.Fatal(err)
	}
	pay := &SessionPayload{UserID: carol.ID, Role: "stale-role", Exp: time.Now().Add(time.Hour).Unix(), Gen: carol.SessionGen}
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/api/events/stream", nil)
	r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, pay))
	if !h.streamSessionStands(r) {
		t.Fatal("a current session does not stand")
	}
	if pay.Role != "stale-role" {
		t.Errorf("the request's payload was rewritten (role %q)", pay.Role)
	}
	// Past its lifetime: ended, without asking the database.
	pay.Exp = time.Now().Add(-time.Second).Unix()
	if h.streamSessionStands(r) {
		t.Error("a session past its lifetime still stands")
	}
	// No session at all: nothing to keep the stream open for.
	if h.streamSessionStands(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Error("a request without a session stands")
	}
}
