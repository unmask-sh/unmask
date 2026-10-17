package main

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// serve -supervise: the process the init script starts only keeps the daemon
// running; the daemon itself is its child.
//
// The daemon cannot survive a fault in the transpiled SQLite: a bad pointer
// there is a fatal runtime error, not a panic a handler could recover, so
// the process dies, and with it every challenge page and verification until
// something starts it again.  systemd (Restart=on-failure) and OpenRC
// (supervise-daemon) do that; SysVinit has nothing of the kind, and on
// 2026-10-18 a host on it served no challenges for the ten minutes until an
// operator ran `service unmask start`.  With -supervise the parent runs
// `unmask serve` with the same arguments as a child, hands it the signals it
// gets, and when the child dies of anything but a clean exit starts it again
// after superviseBackoff.  The parent opens no database and no socket, so it
// has nothing of its own to fail on, and it has the daemon's name, so the
// init script's status and stop find it by the pid they recorded.
//
// A child that keeps dying (superviseLimit crashes within superviseWindow)
// is not started again: the parent exits non-zero and leaves the fault for
// the operator to read in the log, as a crash loop would only hide it.
const (
	superviseBackoff = 5 * time.Second
	superviseLimit   = 10
	superviseWindow  = 10 * time.Minute
)

const superviseFlag = "-supervise"

// stripSupervise reports whether args ask for the supervisor and returns
// them without that flag, for the child.
func stripSupervise(args []string) ([]string, bool) {
	rest := make([]string, 0, len(args))
	found := false
	for _, a := range args {
		if a == superviseFlag || a == "-"+superviseFlag {
			found = true
			continue
		}
		rest = append(rest, a)
	}
	return rest, found
}

// superviseServe runs this binary's `serve` with args as a supervised child
// and returns the exit status for the parent.
func superviseServe(args []string) int {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("supervise: %v", err)
		return 1
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	return supervise(exe, append([]string{"serve"}, args...), superviseBackoff, superviseLimit, superviseWindow, sigs, log.Printf)
}

// supervise runs exe with args until it exits cleanly or a signal arrives,
// starting it again after backoff when it dies otherwise, at most limit
// times within window.  Signals are handed to the child; the exit status is
// the child's last.
func supervise(exe string, args []string, backoff time.Duration, limit int, window time.Duration, sigs <-chan os.Signal, logf func(string, ...any)) int {
	var crashes []time.Time
	for {
		// A stop that arrived while the child was down ends here: there is
		// nothing to signal.
		select {
		case sig := <-sigs:
			logf("supervise: %s; not starting unmask serve again", sig)
			return 0
		default:
		}
		cmd := exec.Command(exe, args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			logf("supervise: cannot start %s: %v", exe, err)
			return 1
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		stopping := false
		var err error
	wait:
		for {
			select {
			case sig := <-sigs:
				// The child gets the signal and ends in its own way; a
				// second one is passed on too.
				stopping = true
				_ = cmd.Process.Signal(sig)
			case err = <-done:
				break wait
			}
		}
		if stopping || err == nil {
			return exitStatus(err)
		}
		now := time.Now()
		crashes = append(crashes, now)
		for len(crashes) > 0 && now.Sub(crashes[0]) > window {
			crashes = crashes[1:]
		}
		if len(crashes) >= limit {
			logf("supervise: unmask serve ended with %v: %d times within %s, not starting it again", err, len(crashes), window)
			return 1
		}
		logf("supervise: unmask serve ended with %v; starting it again in %s", err, backoff)
		select {
		case sig := <-sigs:
			logf("supervise: %s; not starting unmask serve again", sig)
			return 0
		case <-time.After(backoff):
		}
	}
}

// exitStatus is the status a parent reports for its child's end: the
// child's own code, 1 for a signal or any other failure.
func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() >= 0 {
		return ee.ExitCode()
	}
	return 1
}
