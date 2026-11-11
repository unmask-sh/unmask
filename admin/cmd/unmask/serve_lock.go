package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// One serve per database.  A second `unmask serve` started next to a running
// one -- by hand, by a second unit, by an init script that lost its pid file
// -- set up the access-log socket before it got to the admin listener: it
// removed the running daemon's socket and bound its own, then ended on
// "address already in use", taking the path with it.  The first daemon ran
// on with no socket at the path, and the access-log counts, the honeypot's
// automatic bans and the render watch stopped until it was restarted.  With
// the admin on a unix socket, the second one replaced that socket too and
// both ran on the same database.
//
// serve now takes an exclusive lock first, on a file beside the SQLite
// database (or, for MariaDB, beside the access-log socket), and refuses to
// start when another serve holds it.  The lock goes with the process, however
// it ends, so a crash leaves nothing to clean up.  Where the file cannot be
// made, serve says so and starts unguarded, as before.

// serveLockPath: the file the running serve holds its lock on ("" when the
// configuration names no place for one).
func serveLockPath(s settings.Settings) string {
	if d := strings.ToLower(strings.TrimSpace(s.DB.Driver)); d == "" || d == "sqlite" {
		if p := strings.TrimSpace(s.DB.SQLitePath); p != "" {
			return filepath.Join(filepath.Dir(p), ".serve.lock")
		}
	}
	if p := strings.TrimSpace(s.NginxLog.SocketPath); p != "" {
		return filepath.Join(filepath.Dir(p), ".serve.lock")
	}
	return ""
}

// lockServe takes serve's lock and returns its release, or an error naming
// the serve that holds it.
func lockServe(s settings.Settings) (func(), error) {
	path := serveLockPath(s)
	if path == "" {
		return func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		log.Printf("serve: no single-instance lock (%v): a second serve would not be refused", err)
		return func() {}, nil
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		held, _ := os.ReadFile(path)
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			pid := strings.TrimSpace(string(held))
			if pid == "" {
				pid = "unknown"
			}
			return nil, fmt.Errorf("another unmask serve is running on this database (pid %s, holding %s): stop it before starting this one", pid, path)
		}
		log.Printf("serve: no single-instance lock (%v): a second serve would not be refused", err)
		return func() {}, nil
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
