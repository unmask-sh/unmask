package main

import (
	"os"
	"strings"
	"testing"
)

// The SysVinit stop must give the daemon time to close the database (which
// checkpoints the write-ahead log) instead of taking killproc's four-second
// default -- and it must pass its flags in the one order RHEL 6 accepts.
//
// RHEL 6's killproc tests for -p, then -b, then -d, each once and only at the
// front of what is left.  With "-d 30 -p FILE prog" the pidfile is never
// parsed: the program becomes "-p" and the path is read as the signal, so the
// daemon is not stopped at all.  Nothing else catches this -- the install
// matrix never stops the service -- so the order is pinned here.
func TestSysVStopWaitsForTheCheckpoint(t *testing.T) {
	b, err := os.ReadFile("../../../rpm/init.d/unmask.sysv")
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, "killproc") && !strings.HasPrefix(strings.TrimSpace(l), "#") {
			line = strings.TrimSpace(l)
		}
	}
	if line == "" {
		t.Fatal("the init script no longer calls killproc")
	}
	p, d := strings.Index(line, "-p"), strings.Index(line, "-d")
	if p < 0 || d < 0 {
		t.Fatalf("stop must pass both the pidfile and a delay, got: %s", line)
	}
	if p > d {
		t.Errorf("-p must come before -d or RHEL 6 parses neither the pidfile nor the program: %s", line)
	}
	if !strings.Contains(line, "-d 30") {
		t.Errorf("the stop delay should stay at 30s (a checkpoint on a large log): %s", line)
	}
}

// The systemd unit gets the same grace, spelled its own way.
func TestSystemdStopTimeout(t *testing.T) {
	b, err := os.ReadFile("../../../rpm/unmask.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\nTimeoutStopSec=120\n") {
		t.Error("the unit must set TimeoutStopSec so a checkpoint on a large write-ahead log is not killed")
	}
}
