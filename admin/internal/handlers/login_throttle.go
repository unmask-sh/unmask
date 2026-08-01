package handlers

import (
	"net/http"
	"strconv"
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
	mu    sync.Mutex
	cells map[string]*throttleCell

	// Tunables, fixed at construction (tests shorten them).
	failLimit    int           // login failures before the lock trips
	failWindow   time.Duration // failures older than this age out
	lockFor      time.Duration // how long a tripped lock holds
	forgotLimit  int           // forgot-password requests per window
	forgotWindow time.Duration
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
	}
}

// lockedFor returns how much longer the key is locked (0 = not locked).
func (t *loginThrottle) lockedFor(key string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.cells[key]
	if c == nil || !now.Before(c.lockedUntil) {
		return 0
	}
	return c.lockedUntil.Sub(now)
}

// note records one event (a login failure, or a forgot-password request)
// against key and returns the remaining lock if this event tripped or renewed
// it.  limit/window/lock describe the axis being counted.
func (t *loginThrottle) note(key string, now time.Time, limit int, window, lock time.Duration) time.Duration {
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

// clear drops the key's state (a successful login is a clean slate).
func (t *loginThrottle) clear(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.cells, key)
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
func loginKey(ip string) string  { return "l|" + ip }
func forgotKey(ip string) string { return "f|" + ip }

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

// throttle returns the Handler's lazily-built loginThrottle.  Lazy because
// Handler is constructed as a struct literal in several places (main, tests)
// and a nil map would otherwise need every construction site to know about
// this guard.
func (h *Handler) throttle() *loginThrottle {
	h.loginThrottleOnce.Do(func() {
		if h.loginThrottle == nil {
			h.loginThrottle = newLoginThrottle()
		}
	})
	return h.loginThrottle
}
