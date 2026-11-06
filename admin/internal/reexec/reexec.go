// Package reexec re-launches the running daemon in place.
//
// Two things end in it.  The setup wizard switching the database (handlers
// setup.go): the request path and every background worker are bound to the
// handle the daemon started with.  And a daemon that started without its
// database and has found it since (cmd/unmask db_wait.go): the log receiver,
// the ban manager, the event writer and the rollups were never started.  In
// both, only a fresh start binds everything to the database at once, and
// nobody is there to restart the service.
package reexec

import (
	"os"
	"syscall"
)

// execFn is syscall.Exec, a variable so a test can read what would be
// executed without its own process being replaced.
var execFn = syscall.Exec

// Executable is the binary Self starts: the one that is running.
func Executable() string {
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return exe
}

// Self replaces the process with a fresh start of the same binary, with the
// same arguments and environment.  The PID is kept (syscall.Exec), so a SysV
// pidfile and systemd's MainPID stay valid and a supervising parent (serve
// -supervise) sees no child end; the descriptors are not (close-on-exec),
// so the listener and the log socket are bound again by the new start.
//
// It returns only when it failed -- a binary replaced under the running
// daemon by a package upgrade is no longer where it was -- and the process
// then runs on as it was.
func Self() error {
	return execFn(Executable(), os.Args, os.Environ())
}
