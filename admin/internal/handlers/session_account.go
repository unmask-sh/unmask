package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/user"
)

// sessionAccountTimeout bounds the account lookup every admin request makes
// (sessionAccount).  A primary-key read: anything near this long means the
// database is not answering.
const sessionAccountTimeout = 5 * time.Second

// sessionVerdict is what sessionAccount concluded about a session cookie whose
// signature already verified.
type sessionVerdict int

const (
	// sessionValid: the account exists, is enabled and is still on the
	// cookie's session generation.  The payload now carries its current role.
	sessionValid sessionVerdict = iota
	// sessionRevoked: the account was deleted or suspended, or its session
	// generation moved on (a password change or reset, a sign-out).  The
	// cookie is dead and is cleared.
	sessionRevoked
	// sessionUnchecked: the database did not answer.  The cookie is neither
	// honoured nor cleared: this request is refused, and the next one asks
	// again, so a database blip signs nobody out and lets nothing through.
	sessionUnchecked
)

// sessionAccount re-checks a verified session cookie's account against the
// database.  It is the one check both gates make -- AuthMiddleware for every
// admin page, setupSuperadmin for the reconfigure wizard -- so the two cannot
// drift apart again: the wizard had its own copy, without the branch for a
// deleted account, and opened for the cookie of one.
//
// The lookup runs on a context detached from the request's cancellation and
// given a deadline of its own.  On the request's context, a client that hung
// up as soon as it had sent its request made the lookup fail, and a failed
// lookup used to keep the session -- so a cookie revoked by a deletion, a
// suspension, a demotion or a password change reached every handler that
// needs no database read of its own.  Now the lookup is not the client's to
// cancel, and a failure refuses the request (sessionUnchecked).
func (h *Handler) sessionAccount(r *http.Request, pay *SessionPayload) (sessionVerdict, *user.User) {
	if h.UserRepo == nil {
		return sessionValid, nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), sessionAccountTimeout)
	defer cancel()
	u, err := h.UserRepo.GetByID(ctx, pay.UserID)
	switch {
	case errors.Is(err, user.ErrNotFound):
		return sessionRevoked, nil
	case err != nil || u == nil:
		noteSessionUnchecked(pay.UserID, err)
		return sessionUnchecked, nil
	case u.Disabled || u.SessionGen != pay.Gen:
		return sessionRevoked, u
	}
	pay.Role = u.Role
	return sessionValid, u
}

// sessionUncheckedLogged holds the unix second of the last "cannot check the
// session" log line: one a minute is enough to say the database is down,
// where one per request would bury the journal.
var sessionUncheckedLogged atomic.Int64

func noteSessionUnchecked(userID int64, err error) {
	now := time.Now().Unix()
	last := sessionUncheckedLogged.Load()
	if now-last < 60 || !sessionUncheckedLogged.CompareAndSwap(last, now) {
		return
	}
	log.Printf("admin: cannot check the session of user %d against the database (%v); refusing the request until it answers", userID, err)
}

// respondSessionUnchecked answers a request whose session could not be checked
// (sessionUnchecked): 503 with a short retry hint, JSON for the admin API.
// The session cookie is left as it is.
func (h *Handler) respondSessionUnchecked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "5")
	if strings.HasPrefix(r.URL.Path, h.cfg().Server.BasePath+"/admin/api/") {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": 0, "error": "database_unavailable"})
		return
	}
	http.Error(w, "the database did not answer, so the session could not be checked; try again in a moment", http.StatusServiceUnavailable)
}
