package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The supervised child is this test binary: TestMain looks for the role in
// the environment and plays it before any test runs.
const (
	superviseChildEnv  = "UNMASK_SUPERVISE_TEST_CHILD"
	superviseCountFile = "UNMASK_SUPERVISE_TEST_COUNT"
)

func TestMain(m *testing.M) {
	switch os.Getenv(superviseChildEnv) {
	case "":
		os.Exit(m.Run())
	case "exit0":
		superviseCount()
		os.Exit(0)
	case "crash":
		superviseCount()
		os.Exit(2)
	case "crash-twice-then-run":
		// Dies twice, then runs until told to stop, and stops cleanly.
		if superviseCount() <= 2 {
			os.Exit(2)
		}
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGTERM)
		<-sigs
		os.Exit(0)
	}
}

// superviseCount bumps the start counter the test reads and returns it.
func superviseCount() int {
	path := os.Getenv(superviseCountFile)
	n := 0
	if b, err := os.ReadFile(path); err == nil {
		n, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	n++
	_ = os.WriteFile(path, []byte(strconv.Itoa(n)), 0o644)
	return n
}

type superviseRun struct {
	mu    sync.Mutex
	lines []string
}

func (r *superviseRun) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *superviseRun) log() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}

// superviseChild runs supervise over this binary in the given role and
// returns its exit status, the number of starts and the log.
func superviseChild(t *testing.T, role string, limit int, sigs chan os.Signal, act func(starts func() int)) (int, int, string) {
	t.Helper()
	count := filepath.Join(t.TempDir(), "count")
	t.Setenv(superviseChildEnv, role)
	t.Setenv(superviseCountFile, count)
	starts := func() int {
		b, _ := os.ReadFile(count)
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return n
	}
	r := &superviseRun{}
	codeCh := make(chan int, 1)
	go func() {
		codeCh <- supervise(os.Args[0], []string{"-test.run=^$"}, 30*time.Millisecond, limit, time.Minute, sigs, r.logf)
	}()
	if act != nil {
		act(starts)
	}
	select {
	case code := <-codeCh:
		return code, starts(), r.log()
	case <-time.After(20 * time.Second):
		t.Fatalf("supervise did not return; starts=%d log:\n%s", starts(), r.log())
		return 0, 0, ""
	}
}

// A child that dies is started again; one that then runs is stopped by the
// signal handed on, and the parent ends with its clean exit.
func TestSuperviseRestartsACrashedChildAndHandsOnTheStop(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	code, starts, logged := superviseChild(t, "crash-twice-then-run", superviseLimit, sigs, func(starts func() int) {
		for i := 0; i < 200 && starts() < 3; i++ {
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond) // the third child's signal handler is up
		sigs <- syscall.SIGTERM
	})
	if code != 0 || starts != 3 {
		t.Errorf("exit %d after %d starts, want 0 after 3; log:\n%s", code, starts, logged)
	}
	if n := strings.Count(logged, "starting it again"); n != 2 {
		t.Errorf("%d restarts logged, want 2:\n%s", n, logged)
	}
}

// A clean exit is the daemon's own decision: not started again.
func TestSuperviseLeavesACleanExitAlone(t *testing.T) {
	code, starts, logged := superviseChild(t, "exit0", superviseLimit, make(chan os.Signal, 1), nil)
	if code != 0 || starts != 1 || logged != "" {
		t.Errorf("exit %d after %d starts, log %q; want 0, 1, nothing", code, starts, logged)
	}
}

// A child that keeps dying is given up on at the limit, with the parent
// failing so the init script's status says so.
func TestSuperviseGivesUpOnACrashLoop(t *testing.T) {
	code, starts, logged := superviseChild(t, "crash", 3, make(chan os.Signal, 1), nil)
	if code != 1 || starts != 3 || !strings.Contains(logged, "not starting it again") {
		t.Errorf("exit %d after %d starts, want 1 after 3; log:\n%s", code, starts, logged)
	}
}

func TestStripSupervise(t *testing.T) {
	rest, ok := stripSupervise([]string{"-supervise", "-config", "/etc/unmask/config.yml"})
	if !ok || strings.Join(rest, " ") != "-config /etc/unmask/config.yml" {
		t.Errorf("stripped %q ok=%v", rest, ok)
	}
	if rest, ok := stripSupervise([]string{"-config", "x"}); ok || len(rest) != 2 {
		t.Errorf("without the flag: %q ok=%v", rest, ok)
	}
}
