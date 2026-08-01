package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The identity comes off the data directory rather than a hardcoded account
// name, so an install running the service under a different user still gets
// the right answer.
func TestDaemonIdentityReadsTheDataDirOwner(t *testing.T) {
	dir := t.TempDir()
	old := dataDirForOwner
	dataDirForOwner = dir
	t.Cleanup(func() { dataDirForOwner = old })

	uid, gid, name, err := daemonIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if uid != os.Getuid() || gid != os.Getgid() {
		t.Errorf("identity = %d/%d, want this process's %d/%d", uid, gid, os.Getuid(), os.Getgid())
	}
	if name == "" {
		t.Error("identity has no name, not even a numeric one")
	}
}

// A missing data directory is a fresh install, not a failure: config-init has
// to be able to run before anything exists.
func TestDropIsANoOpWithoutADataDir(t *testing.T) {
	old := dataDirForOwner
	dataDirForOwner = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { dataDirForOwner = old })

	if _, err := dropPrivilegesIfRoot(); err != nil {
		t.Errorf("a missing data dir must not fail the command: %v", err)
	}
}

// Non-root is left alone: an operator running the CLI as themselves keeps
// their own identity and gets the usual permission errors if they lack access.
func TestDropIsANoOpWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	note, err := dropPrivilegesIfRoot()
	if err != nil || note != "" {
		t.Errorf("non-root run should do nothing, got note=%q err=%v", note, err)
	}
}

// The escape hatch must be honoured and must SAY so -- an operator who sets it
// is opting into root-owned files, and finding that out later from a broken
// daemon is the failure mode this whole change exists to remove.
func TestEscapeHatchIsAnnounced(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to exercise the root path")
	}
	t.Setenv(noPrivDropEnv, "1")
	note, err := dropPrivilegesIfRoot()
	if err != nil {
		t.Fatalf("escape hatch should not error: %v", err)
	}
	if note == "" {
		t.Error("the escape hatch dropped nothing and said nothing")
	}
}

// ownershipProblems is what doctor reports: a file the daemon user cannot
// write is listed, one it can is not.  Run as the current user, so "the daemon
// user" is us and a root-owned file stands in for the real-world residue.
func TestOwnershipProblemsFindsUnwritableFiles(t *testing.T) {
	dir := t.TempDir()
	mine := filepath.Join(dir, "mine")
	if err := os.WriteFile(mine, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := ownershipProblems([]string{dir}, os.Getuid(), os.Getgid()); len(got) != 0 {
		t.Errorf("a file we own is not a problem, got %v", got)
	}

	// A file owned by someone else with no group/world write is the shape that
	// broke the fleet (root:root 0640 mmdb).  Simulated by claiming a
	// different uid rather than by needing root in the test.
	if got := ownershipProblems([]string{dir}, os.Getuid()+1, os.Getgid()+1); len(got) == 0 {
		t.Error("a file the daemon user cannot write was not reported")
	}

	// Group-writable and we are in the group: usable, so not a problem.
	shared := filepath.Join(dir, "shared")
	if err := os.WriteFile(shared, []byte("x"), 0o660); err != nil {
		t.Fatal(err)
	}
	// Chmod explicitly: the umask strips the group-write bit from the create
	// mode, which is exactly the bit under test.
	if err := os.Chmod(shared, 0o660); err != nil {
		t.Fatal(err)
	}
	for _, p := range ownershipProblems([]string{dir}, os.Getuid()+1, os.Getgid()) {
		if p == shared {
			t.Error("a group-writable file in our group is usable and must not be reported")
		}
	}
}

// serve must go through the same path: a hand-started `sudo unmask serve`
// otherwise writes root-owned state (SQLite -wal / -shm above all) that the
// service-managed daemon then cannot use.
func TestServeIsNotExemptFromTheDrop(t *testing.T) {
	if privDropExempt["serve"] {
		t.Error("serve is exempt; a root-started serve would recreate the problem")
	}
	if len(privDropExempt) != 0 {
		t.Errorf("exemptions must be justified in the map's comment, found %v", privDropExempt)
	}
}
