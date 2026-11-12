package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// migratedDB is a fresh SQLite database with every migration applied, which
// is what the daemon runs on: the table the counters live in is there.
func migratedDB(t *testing.T) *db.DB {
	t.Helper()
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dbTempDir(t), "t.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	return conn
}

func dbThrottle(conn *db.DB) *loginThrottle {
	tr := newLoginThrottle()
	tr.store = &loginThrottleStore{db: conn}
	return tr
}

// The counters live in the database: the lock a run of failures trips is
// seen by another throttle on the same database (another node, or this one
// after a restart), a successful sign-in clears it for both, and the memory
// cells stay empty throughout.
func TestLoginThrottleCountsInTheDatabase(t *testing.T) {
	conn := migratedDB(t)
	a, b := dbThrottle(conn), dbThrottle(conn)
	now := time.Unix(1_800_000_000, 0)
	key := loginKey("203.0.113.7")

	for i := 0; i < a.failLimit-1; i++ {
		if d := a.note(key, now, a.failLimit, a.failWindow, a.lockFor); d != 0 {
			t.Fatalf("failure %d already locked", i+1)
		}
	}
	// The other node sees the count so far: its one failure trips the lock.
	if d := b.note(key, now, b.failLimit, b.failWindow, b.lockFor); d != b.lockFor {
		t.Fatalf("failure %d on the other node should trip the lock for %v, got %v", b.failLimit, b.lockFor, d)
	}
	if d := a.lockedFor(key, now.Add(time.Minute)); d <= 0 {
		t.Error("the lock is not seen on the first node")
	}
	if d := dbThrottle(conn).lockedFor(key, now.Add(time.Minute)); d <= 0 {
		t.Error("the lock did not survive a restart (a fresh throttle on the same database)")
	}
	// Another event while locked renews nothing and reports the remainder.
	if d := a.note(key, now.Add(5*time.Minute), a.failLimit, a.failWindow, a.lockFor); d != a.lockFor-5*time.Minute {
		t.Errorf("event under the lock answered %v, want the %v left", d, a.lockFor-5*time.Minute)
	}
	if d := a.lockedFor(key, now.Add(a.lockFor+time.Second)); d != 0 {
		t.Error("the lock outlived its duration")
	}
	if d := a.lockedFor(loginKey("198.51.100.9"), now); d != 0 {
		t.Error("an unrelated address got locked")
	}
	// A successful sign-in takes the account's own failures off the count,
	// for every node; another account's stay.
	later := now.Add(time.Hour)
	own, other := loginOwnKey("203.0.113.7", "alice"), loginOwnKey("203.0.113.7", "mallory")
	for i := 0; i < a.failLimit-1; i++ {
		a.noteOwn(own, later)
		a.note(key, later, a.failLimit, a.failWindow, a.lockFor)
	}
	a.forgive(key, other, later) // mallory signs in: nothing of alice's goes
	b.forgive(key, own, later)   // alice signs in, on the other node
	for i := 0; i < b.failLimit-1; i++ {
		if d := b.note(key, later, b.failLimit, b.failWindow, b.lockFor); d != 0 {
			t.Fatalf("failure %d after the account's own login locked: its failures were not taken off the shared count", i+1)
		}
	}
	a.noteOwn(own, later)
	a.forgive(key, other, later)
	if d := a.note(key, later, a.failLimit, a.failWindow, a.lockFor); d == 0 {
		t.Error("a login as another account kept the address from locking at its tenth failure")
	}
	if len(a.cells) != 0 || len(b.cells) != 0 {
		t.Errorf("the memory cells were used (%d / %d) although the database answered", len(a.cells), len(b.cells))
	}
}

// Failures older than the window do not count: the window opens anew.  And
// the two axes keep their own rows.
func TestLoginThrottleWindowInTheDatabase(t *testing.T) {
	conn := migratedDB(t)
	tr := dbThrottle(conn)
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < tr.failLimit-1; i++ {
		tr.note(loginKey("a"), now, tr.failLimit, tr.failWindow, tr.lockFor)
	}
	later := now.Add(tr.failWindow + time.Second)
	if d := tr.note(loginKey("a"), later, tr.failLimit, tr.failWindow, tr.lockFor); d != 0 {
		t.Error("stale failures still counted toward the lock")
	}
	for i := 0; i < tr.forgotLimit-1; i++ {
		if d := tr.note(forgotKey("a"), later, tr.forgotLimit, tr.forgotWindow, tr.forgotWindow); d != 0 {
			t.Fatalf("request %d already capped", i+1)
		}
	}
	if d := tr.note(forgotKey("a"), later, tr.forgotLimit, tr.forgotWindow, tr.forgotWindow); d == 0 {
		t.Fatal("the forgot-password cap never tripped")
	}
	if d := tr.lockedFor(loginKey("a"), later); d != 0 {
		t.Error("the forgot-password cap leaked into the login axis")
	}
}

// Without the table (a database from before the migration, the tests' own
// schema) the counters fall back to this node's memory and keep working.
func TestLoginThrottleFallsBackToMemoryWithoutTheTable(t *testing.T) {
	h := newTestHandler(t)
	tr := h.throttle()
	if tr.store == nil {
		t.Fatal("a handler with a database should have the store")
	}
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < tr.failLimit-1; i++ {
		if d := tr.note(loginKey("x"), now, tr.failLimit, tr.failWindow, tr.lockFor); d != 0 {
			t.Fatalf("failure %d already locked", i+1)
		}
	}
	if d := tr.note(loginKey("x"), now, tr.failLimit, tr.failWindow, tr.lockFor); d != tr.lockFor {
		t.Fatalf("the lock did not trip in memory: %v", d)
	}
	if len(tr.cells) == 0 {
		t.Error("the memory cells were not used")
	}
}

// While a schema update holds the database's writes the memory counts,
// so a sign-in does not wait on the lock.
func TestLoginThrottleUsesMemoryWhileWritesAreHeld(t *testing.T) {
	conn := migratedDB(t)
	tr := dbThrottle(conn)
	conn.HoldWrites(true)
	defer conn.HoldWrites(false)
	now := time.Unix(1_800_000_000, 0)
	tr.note(loginKey("h"), now, tr.failLimit, tr.failWindow, tr.lockFor)
	if len(tr.cells) != 1 {
		t.Errorf("under a hold the event should be counted in memory; cells = %d", len(tr.cells))
	}
	var n int64
	if err := conn.QueryRow(`SELECT COUNT(*) FROM unmask_login_throttle`).Scan(&n); err != nil || n != 0 {
		t.Errorf("rows written under the hold: %d (%v)", n, err)
	}
}

// Through the handler, across a restart: the address that hammered the
// login is still locked when a new daemon (a new Handler on the same
// database) answers its next attempt.
func TestLoginPostLockSurvivesARestart(t *testing.T) {
	conn := migratedDB(t)
	post := func(h *Handler) *httptest.ResponseRecorder {
		form := url.Values{"username": {"admin"}, "password": {"wrong"}}
		req := loginRequest(h, form) // with the form's CSRF token, so the refusal is the lock's
		req.RemoteAddr = "203.0.113.7:44321"
		rr := httptest.NewRecorder()
		h.AdminLoginPost(rr, req)
		return rr
	}
	first := &Handler{DB: conn}
	limit := first.throttle().failLimit
	for i := 0; i < limit-1; i++ {
		if rr := post(first); rr.Code != http.StatusFound {
			t.Fatalf("failure %d: want the invalid-login redirect, got %d", i+1, rr.Code)
		}
	}
	if rr := post(first); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("failure %d should answer 429, got %d", limit, rr.Code)
	}
	restarted := &Handler{DB: conn}
	if rr := post(restarted); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("after a restart the locked address answered %d, want 429", rr.Code)
	}
}
