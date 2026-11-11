package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A second serve on the same database is refused before it touches a socket,
// naming the serve that runs; once that one is gone, the next one starts.
func TestLockServeRefusesASecond(t *testing.T) {
	var s settings.Settings
	s.DB.Driver = "sqlite"
	s.DB.SQLitePath = filepath.Join(t.TempDir(), "unmask.sqlite")
	release, err := lockServe(s)
	if err != nil {
		t.Fatalf("the first serve: %v", err)
	}
	lock := filepath.Join(filepath.Dir(s.DB.SQLitePath), ".serve.lock")
	if b, _ := os.ReadFile(lock); strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
		t.Errorf("the lock names %q, want this pid", b)
	}
	if _, err := lockServe(s); err == nil || !strings.Contains(err.Error(), "another unmask serve is running") || !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Errorf("a second serve: %v", err)
	}
	release()
	again, err := lockServe(s)
	if err != nil {
		t.Fatalf("after the first one ended: %v", err)
	}
	again()
}

func TestServeLockPath(t *testing.T) {
	var s settings.Settings
	s.DB.SQLitePath = "/var/lib/unmask/unmask.sqlite"
	s.NginxLog.SocketPath = "/run/unmask/log.sock"
	if got := serveLockPath(s); got != "/var/lib/unmask/.serve.lock" {
		t.Errorf("sqlite: %s", got)
	}
	s.DB.Driver = "mysql"
	if got := serveLockPath(s); got != "/run/unmask/.serve.lock" {
		t.Errorf("mariadb: %s", got)
	}
	s.NginxLog.SocketPath = ""
	if got := serveLockPath(s); got != "" {
		t.Errorf("nowhere: %s", got)
	}
	// A directory that cannot hold the file: serve starts unguarded.
	s.DB.Driver, s.DB.SQLitePath = "sqlite", "/nonexistent-dir/x/unmask.sqlite"
	if release, err := lockServe(s); err != nil {
		t.Errorf("an unwritable place refused the start: %v", err)
	} else {
		release()
	}
}
