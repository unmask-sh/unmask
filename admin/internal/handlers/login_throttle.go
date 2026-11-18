package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// loginThrottle is the admin credential endpoints' own brute-force guard:
// per-IP login-failure lockout, and a per-IP cap on forgot-password requests
// (each of which sends mail and mints a reset token, so the REQUEST is the
// cost, not some notion of failure).
//
// This lives in the application because the application is what is being
// attacked.  The rate-limit zone that used to stand here (unmask_admin_login,
// a shipped preset) never fired for the traffic it was meant to stop: the
// /unmask/admin/ protected path hands every client that can even reach the
// login POST a _bv cookie, and challenge-mode zones deliberately do not count
// _bv holders.  A handler-side counter has none of those interactions -- no
// cookie exemptions, no deployment-mode split, no nginx-version constraint.
//
// Scope is per-IP on purpose.  A per-ACCOUNT lockout would hand an attacker a
// denial-of-service button against the operator (fail ten passwords, admin
// locked out); per-IP makes the attacker spread across addresses without ever
// touching the operator's own access.
type loginThrottle struct {
	// store keeps the counters in the database (login_throttle_db.go), so
	// they outlive a restart and are shared by every node on a shared
	// database.  The cells below are the fallback: no database yet, its
	// writes held by a schema update, or an error on the way.
	store *loginThrottleStore

	mu    sync.Mutex
	cells map[string]*throttleCell

	// Tunables, fixed at construction (tests shorten them).
	failLimit    int           // login failures before the lock trips
	failWindow   time.Duration // failures older than this age out
	lockFor      time.Duration // how long a tripped lock holds
	forgotLimit  int           // forgot-password requests per window
	forgotWindow time.Duration
	resetEvery   time.Duration // an account is sent one reset link in this time, at most
}

type throttleCell struct {
	events      []time.Time
	lockedUntil time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{
		cells:        map[string]*throttleCell{},
		failLimit:    10,
		failWindow:   15 * time.Minute,
		lockFor:      15 * time.Minute,
		forgotLimit:  5,
		forgotWindow: 15 * time.Minute,
		resetEvery:   resetLinkEvery,
	}
}

// resetLinkEvery: the forgot-password page sends an account one link in
// this time, at most (resetLinkRecentlySent).  The page says the number
// (forgot.sent); a test holds the two together.
const resetLinkEvery = 10 * time.Minute

// resetLinkKey is the key under which an account's last reset or setup link
// is remembered for resetEvery.
func resetLinkKey(userID int64) string { return "r|" + strconv.FormatInt(userID, 10) }

// resetLinkRecentlySent reports whether the account was sent a reset or
// setup link less than resetEvery ago, and for how much longer that holds.
//
// The account keeps one link at a time (one column, and only the hash of the
// token, so a link cannot be sent again), and every request for a link used
// to replace it.  Whoever knew a user name or an address could therefore
// keep the owner's link dead -- ask again the moment the mail went out, from
// as many addresses as the per-address cap needed -- and fill the owner's
// mailbox while doing it.  Now a request inside resetEvery of the last link
// issues nothing: the link in the owner's mailbox stays the valid one for at
// least that long, and the account gets one mail in that time whoever asks.
func (t *loginThrottle) resetLinkRecentlySent(userID int64, now time.Time) time.Duration {
	return t.lockedFor(resetLinkKey(userID), now)
}

// noteResetLink records that the account has just been sent a link.
func (t *loginThrottle) noteResetLink(userID int64, now time.Time) {
	t.note(resetLinkKey(userID), now, 1, t.resetEvery, t.resetEvery)
}

// lockedForMem is lockedFor on this node's memory.
func (t *loginThrottle) lockedForMem(key string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.cells[key]
	if c == nil || !now.Before(c.lockedUntil) {
		return 0
	}
	return c.lockedUntil.Sub(now)
}

// noteMem is note on this node's memory.
func (t *loginThrottle) noteMem(key string, now time.Time, limit int, window, lock time.Duration) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	c := t.cells[key]
	if c == nil {
		c = &throttleCell{}
		t.cells[key] = c
	}
	if now.Before(c.lockedUntil) {
		return c.lockedUntil.Sub(now)
	}
	keep := c.events[:0]
	for _, e := range c.events {
		if now.Sub(e) < window {
			keep = append(keep, e)
		}
	}
	c.events = append(keep, now)
	if len(c.events) >= limit {
		c.lockedUntil = now.Add(lock)
		c.events = c.events[:0]
		return lock
	}
	return 0
}

// forgiveMem is forgive on this node's memory: as many of key's newest
// events as own has inside the window are dropped, and own's cell with them.
func (t *loginThrottle) forgiveMem(key, own string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	oc := t.cells[own]
	if oc == nil {
		return
	}
	n := 0
	for _, e := range oc.events {
		if now.Sub(e) < t.failWindow {
			n++
		}
	}
	delete(t.cells, own)
	c := t.cells[key]
	if c == nil || n == 0 {
		return
	}
	if n >= len(c.events) {
		c.events = c.events[:0]
	} else {
		c.events = c.events[:len(c.events)-n]
	}
	if len(c.events) == 0 && !now.Before(c.lockedUntil) {
		delete(t.cells, key)
	}
}

// pruneLocked drops expired cells so an address sweep cannot grow the map
// without bound.  Called with t.mu held, from note's hot path -- the map only
// grows on events that themselves imply someone is hammering the endpoints,
// and a full sweep over even tens of thousands of cells is microseconds.
func (t *loginThrottle) pruneLocked(now time.Time) {
	if len(t.cells) < 4096 {
		return
	}
	for k, c := range t.cells {
		expiredLock := !now.Before(c.lockedUntil)
		fresh := false
		for _, e := range c.events {
			if now.Sub(e) < t.failWindow || now.Sub(e) < t.forgotWindow {
				fresh = true
				break
			}
		}
		if expiredLock && !fresh {
			delete(t.cells, k)
		}
	}
}

// loginKey / forgotKey namespace the two axes inside one cell map, so a flood
// of forgot-password requests cannot age out login-failure history.
func loginKey(ip string) string  { return "l|" + throttleAddr(ip) }
func forgotKey(ip string) string { return "f|" + throttleAddr(ip) }

// loginOwnKey is the key of the failures one address made for one account:
// the name as it was typed, folded and hashed so that the key has a fixed
// length whatever was typed.
func loginOwnKey(ip, username string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username))))
	return "o|" + throttleAddr(ip) + "|" + hex.EncodeToString(sum[:8])
}

// ownPasswordKey is the key of the current-password checks that an
// account's own sessions have failed (Handler.checkOwnPassword).  By
// account, where the login's count is by address, and for the reason the
// login's is not: nobody without a session of the account can reach these
// checks, so the count is no way for a stranger to lock an operator out --
// and whoever does hold a session can guess from as many addresses as they
// like.
func ownPasswordKey(userID int64) string { return "p|" + strconv.FormatInt(userID, 10) }

// throttleAddr is the address the counters are kept by: an IPv4 address as
// it is, an IPv6 address as its /64.  A /64 is the smallest block a
// subscriber is handed and the client in it can send from any of its 2^64
// addresses, so counted by the full address an IPv6 attacker had a fresh
// counter for every attempt.  Anything that does not parse (the tests' bare
// names, an empty peer) is kept as it is.
//
// cookies.bindIP folds the same way for the _bv seed, but that one is a
// wire format shared with the nginx plugin (the prefix as hex, bind keys
// passed through); the throttle keeps its own reading rather than take on
// that contract for a key nothing else ever sees.
func throttleAddr(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if a.Is4() || a.Is4In6() {
		return a.Unmap().String()
	}
	p, err := a.WithZone("").Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// tooManyLoginAttempts answers a locked address: 429 with Retry-After, no
// redirect (a locked client has nothing useful to render) and no i18n (this
// is an abuse response; Retry-After is the contract).
func tooManyLoginAttempts(w http.ResponseWriter, d time.Duration) {
	secs := int(d.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	http.Error(w, "too many attempts; try again later", http.StatusTooManyRequests)
}

// passwordCheckBusy answers a login the daemon could not check because every
// password-hashing slot stayed taken (user.ErrBusy): 503 with Retry-After.
// Not a failure for the lockout -- the password was never looked at -- and
// not the invalid-login redirect, which would read as "wrong password".
func passwordCheckBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "10")
	http.Error(w, "the server is busy checking other sign-ins; try again shortly", http.StatusServiceUnavailable)
}

// throttle returns the Handler's lazily-built loginThrottle.  Lazy because
// Handler is constructed as a struct literal in several places (main, tests)
// and a nil map would otherwise need every construction site to know about
// this guard.
func (h *Handler) throttle() *loginThrottle {
	h.loginThrottleOnce.Do(func() {
		if h.loginThrottle == nil {
			h.loginThrottle = newLoginThrottle()
		}
		if h.loginThrottle.store == nil && h.DB != nil {
			h.loginThrottle.store = &loginThrottleStore{db: h.DB}
		}
	})
	return h.loginThrottle
}
