package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/handlers"
	"github.com/unmask-sh/unmask/admin/internal/live"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// waitRig drives dbWait.run with nothing real in it: a database that
// answers when the test says so, a restart that only counts, and a clock that
// moves by exactly what the loop asked to sleep -- so the backoff and the
// log's pace are read off as numbers, and no test waits for anything.
type waitRig struct {
	clock time.Time
	slept []time.Duration
	// opens counts the tries; openErr answers the n-th (from 1).
	opens   int
	openErr func(n int) error
	// restarts counts the restarts; restartErr answers the n-th (from 1).
	restarts   int
	restartErr func(n int) error
	// stopAfter ends the context once this many sleeps have been asked for
	// (0: never), as the shutdown does.
	stopAfter int
	cancel    context.CancelFunc
	// lines are the log, each with the rig's time when it was written.
	lines []string
	at    []time.Duration
	start time.Time
}

func newWaitRig() *waitRig {
	t0 := time.Date(2026, 1, 15, 3, 0, 0, 0, time.UTC)
	return &waitRig{clock: t0, start: t0}
}

func (r *waitRig) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.cancel = cancel
	w := dbWait{
		open: func(context.Context) error {
			r.opens++
			if r.openErr == nil {
				return errors.New("dial tcp 192.0.2.5:3306: connect: connection refused")
			}
			return r.openErr(r.opens)
		},
		restart: func() error {
			r.restarts++
			if r.restartErr == nil {
				return nil
			}
			return r.restartErr(r.restarts)
		},
		sleep: func(ctx context.Context, d time.Duration) bool {
			if r.stopAfter > 0 && len(r.slept) >= r.stopAfter {
				cancel()
				return false
			}
			r.slept = append(r.slept, d)
			r.clock = r.clock.Add(d)
			return ctx.Err() == nil
		},
		now: func() time.Time { return r.clock },
		logf: func(format string, args ...any) {
			r.lines = append(r.lines, fmt.Sprintf(format, args...))
			r.at = append(r.at, r.clock.Sub(r.start))
		},
	}
	done := make(chan struct{})
	go func() { defer close(done); w.run(ctx) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the wait did not end")
	}
}

func secs(ds ...int) []time.Duration {
	out := make([]time.Duration, len(ds))
	for i, d := range ds {
		out[i] = time.Duration(d) * time.Second
	}
	return out
}

// The retries start two seconds after the failed start, double, and settle
// at thirty; the try that finds the database restarts the daemon, once, and
// the loop is over.
func TestDBWaitBacksOffThenRestartsOnce(t *testing.T) {
	r := newWaitRig()
	r.openErr = func(n int) error {
		if n < 8 {
			return errors.New("connection refused")
		}
		return nil
	}
	r.run(t)
	if want := secs(2, 4, 8, 16, 30, 30, 30, 30); !slices.Equal(r.slept, want) {
		t.Errorf("waits %v, want %v", r.slept, want)
	}
	if r.opens != 8 || r.restarts != 1 {
		t.Errorf("%d tries and %d restart(s), want 8 and 1", r.opens, r.restarts)
	}
	last := r.lines[len(r.lines)-1]
	if !strings.Contains(last, "answers again") || !strings.Contains(last, "try 8") {
		t.Errorf("the last line does not report the database back: %q", last)
	}
}

// A database that stays away is named in the log once a minute, not once a
// try: the start logged the first failure, so the first line here comes a
// minute later, and an hour of waiting is sixty lines however often it tried.
func TestDBWaitSaysSoOnceAMinute(t *testing.T) {
	r := newWaitRig()
	r.stopAfter = 123 // 2+4+8+16+30 s, then 118 tries thirty seconds apart: an hour
	r.run(t)
	if r.restarts != 0 {
		t.Fatalf("restarted %d time(s) with no database", r.restarts)
	}
	if len(r.lines) != 60 {
		t.Errorf("%d line(s) in an hour, want 60: %v", len(r.lines), r.lines[:min(len(r.lines), 5)])
	}
	for i, line := range r.lines {
		if !strings.Contains(line, "still unreachable") || !strings.Contains(line, "connection refused") {
			t.Errorf("line %d does not name the error: %q", i, line)
		}
		if i == 0 && r.at[i] < time.Minute {
			t.Errorf("the first line came %s after the start's own", r.at[i])
		}
		if i > 0 && r.at[i]-r.at[i-1] < time.Minute {
			t.Errorf("lines %d and %d are %s apart", i-1, i, r.at[i]-r.at[i-1])
		}
	}
}

// The shutdown ends the wait where it stands, and a try it interrupted
// restarts nothing even when that try found the database: the service
// manager asked this process to stop.
func TestDBWaitStopsForTheShutdown(t *testing.T) {
	r := newWaitRig()
	r.stopAfter = 3
	r.run(t)
	if r.opens != 3 || r.restarts != 0 {
		t.Errorf("stopped during the fourth wait: %d tries, %d restarts, want 3 and 0", r.opens, r.restarts)
	}

	r = newWaitRig()
	r.openErr = func(int) error {
		r.cancel() // the stop arrives while the database is being tried
		return nil // ... and the try finds it
	}
	r.run(t)
	if r.opens != 1 || r.restarts != 0 {
		t.Errorf("a stop during the try: %d tries, %d restarts, want 1 and 0", r.opens, r.restarts)
	}
}

// A restart that fails (the binary replaced under the daemon) leaves the
// daemon as it was and the wait going: it is said once, tried again with the
// next round, and over when one succeeds.
func TestDBWaitTriesAFailedRestartAgain(t *testing.T) {
	r := newWaitRig()
	r.openErr = func(int) error { return nil }
	r.restartErr = func(n int) error {
		if n < 3 {
			return errors.New("fork/exec /usr/sbin/unmask (deleted): no such file or directory")
		}
		return nil
	}
	r.run(t)
	if r.opens != 3 || r.restarts != 3 {
		t.Errorf("%d tries, %d restarts, want 3 and 3", r.opens, r.restarts)
	}
	if want := secs(2, 4, 8); !slices.Equal(r.slept, want) {
		t.Errorf("waits %v, want %v", r.slept, want)
	}
	failed := 0
	for _, line := range r.lines {
		if strings.Contains(line, "could not start over") {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("the failed restart was said %d time(s) within a minute, want 1: %v", failed, r.lines)
	}
}

// probeDB is one try: the configured database opened and let go of again.
func TestProbeDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.sqlite")
	if err := probeDB(context.Background(), settings.DB{Driver: "sqlite", SQLitePath: path}); err != nil {
		t.Fatalf("a database that opens: %v", err)
	}
	if err := probeDB(context.Background(), settings.DB{Driver: "no-such-driver"}); err == nil {
		t.Error("a database that cannot be opened: no error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Either answer is in time; what matters is that a stopped context is
	// not kept waiting for the open.
	done := make(chan struct{})
	go func() { _ = probeDB(ctx, settings.DB{Driver: "sqlite", SQLitePath: path}); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("probeDB did not return for an ended context")
	}
}

// waitingRouter is the router of a daemon on a set-up install that started
// without its database, as cmdServe builds it: no handle, no repositories,
// no log receiver, no ban manager.
func waitingRouter(t *testing.T) (settings.Settings, *http.ServeMux) {
	t.Helper()
	config, _ := migrateConfig(t, "")
	s, err := settings.Load(config)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = filepath.Join(t.TempDir(), "nginx")
	h := &handlers.Handler{
		DBWaiting: true, ConfigPath: config, Version: "0.0.0", HostID: "db-wait-test",
		Live: live.New(), RateLimiter: ratelimit.New(),
		Notifier: notifier.New(handlers.NotifierConfigFrom(s.Notifications, "db-wait-test")),
	}
	h.SetSettings(s)
	handlers.SetSetupTokenDir(t.TempDir())
	_ = os.Remove(handlers.SetupTokenPath)
	return s, buildRouter(s, h)
}

// Every route under {base}/admin/ of a daemon that waits for its database
// answers 503 -- taken from the router itself, so a route added later is
// covered -- and none of them redirects to the setup wizard or breaks on the
// handle that is not there.  Three need no database and keep their answers:
// the wizard's done page, the sign-out (403 here, for want of a session),
// and the sink for what the browser refuses under the admin's script policy
// -- the 503 page carries that policy too, and a report about it is a log
// line (400 here: the walk posts an empty body).
func TestDBWaitingEveryAdminRouteIs503(t *testing.T) {
	s, mux := waitingRouter(t)
	base := s.Server.BasePath
	other := map[string]int{
		base + "/admin/setup/done": http.StatusOK,
		base + "/admin/logout":     http.StatusForbidden,
		base + "/admin/csp-report": http.StatusBadRequest,
	}
	for _, r := range adminRoutes(t, mux, base) {
		req := httptest.NewRequest(r.method, r.path, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := serve(mux, req)
		want := http.StatusServiceUnavailable
		if code, ok := other[r.path]; ok {
			want = code
		}
		if rec.Code != want {
			t.Errorf("%s: %d (Location %q), want %d", r.pattern, rec.Code, rec.Header().Get("Location"), want)
		}
	}
}

// What needs no database goes on being served meanwhile: the challenge
// page, its script, the verification endpoints' own answers, the forward-auth
// decision, liveness.  Readiness and the metrics say the database is away.
func TestDBWaitingStillServesTheChallenge(t *testing.T) {
	s, mux := waitingRouter(t)
	base := s.Server.BasePath
	const browser = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
	get := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:5555"
		req.Header.Set("User-Agent", browser)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		return serve(mux, req)
	}

	page := get(http.MethodGet, base+"/challenge/", "")
	if page.Code != http.StatusForbidden || !strings.Contains(page.Body.String(), "challenge.js") {
		t.Errorf("the challenge page: %d, script in it = %v; want the 403 page that runs the challenge",
			page.Code, strings.Contains(page.Body.String(), "challenge.js"))
	}
	for path, want := range map[string]int{
		base + "/static/challenge.js": http.StatusOK,
		base + "/healthz":             http.StatusOK,
		base + "/readyz":              http.StatusServiceUnavailable,
		base + "/metrics":             http.StatusOK,
		base + "/api/check":           http.StatusUnauthorized, // the decision: challenge
	} {
		if rec := get(http.MethodGet, path, ""); rec.Code != want {
			t.Errorf("GET %s: %d, want %d", path, rec.Code, want)
		}
	}
	if body := get(http.MethodGet, base+"/healthz", "").Body.String(); body != "ok\n" {
		t.Errorf("healthz body %q, want %q", body, "ok\n")
	}
	if body := get(http.MethodGet, base+"/readyz", "").Body.String(); body != "database unavailable\n" {
		t.Errorf("readyz body %q, want %q", body, "database unavailable\n")
	}
	if body := get(http.MethodGet, base+"/metrics", "").Body.String(); !strings.Contains(body, "unmask_db_up 0\n") {
		t.Errorf("the metrics do not say unmask_db_up 0")
	}
	// The beacon and the verification answer for themselves (a refusal of
	// this request's content), not with a handler that broke.
	for _, path := range []string{base + "/api/debug", base + "/api/verify", base + "/api/bvj"} {
		if rec := get(http.MethodPost, path, `{"phase":"load","flags":0}`); rec.Code >= 500 {
			t.Errorf("POST %s: %d", path, rec.Code)
		}
	}
}
