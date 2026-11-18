package repocheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The SysVinit script appends the daemon's output to /var/log/unmask.log.
// The log names visitors' addresses and the user names tried at the sign-in,
// and the script made it under root's umask: 0644, every local user's to
// read.  It is 0640 -- made so, and set so at every start, which also
// tightens a log from before and the copies logrotate made of it.
//
// The three lines are run here as the script has them, on a directory of
// the test's own, with chown stood in for (it needs root).
func TestSysVInitKeepsTheLogPrivate(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "rpm", "init.d", "unmask.sysv"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(src), "\n") {
		tl := strings.TrimSpace(l)
		if strings.HasPrefix(tl, `[ -e "$logfile" ] ||`) || strings.HasPrefix(tl, `chown "$user:$user" "$logfile"`) || strings.HasPrefix(tl, `chmod 0640 "$logfile"`) {
			lines = append(lines, tl)
		}
	}
	if len(lines) != 3 {
		t.Fatalf("found %d of the three lines that make and tighten the log in unmask.sysv:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	run := func(dir string) {
		t.Helper()
		bin := filepath.Join(dir, "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "chown"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		script := "umask 022\nuser=unmask\nlogfile=" + filepath.Join(dir, "unmask.log") + "\n" + strings.Join(lines, "\n") + "\nexit 0\n"
		cmd := exec.Command("sh", "-c", script)
		cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH")}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	}
	mode := func(p string) os.FileMode {
		t.Helper()
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return st.Mode().Perm()
	}

	// A first start: the log is made, private.
	fresh := t.TempDir()
	run(fresh)
	if m := mode(filepath.Join(fresh, "unmask.log")); m != 0o640 {
		t.Errorf("a new log is %04o, want 0640", m)
	}

	// A host that ran the script from before: the log and its rotated
	// copies are 0644, and a file that is not the log's is somebody else's.
	old := t.TempDir()
	for _, name := range []string{"unmask.log", "unmask.log-20261101", "unmask.log-20261108.gz", "unmask.logbook", "other.log"} {
		if err := os.WriteFile(filepath.Join(old, name), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run(old)
	for name, want := range map[string]os.FileMode{
		"unmask.log": 0o640, "unmask.log-20261101": 0o640, "unmask.log-20261108.gz": 0o640,
		"unmask.logbook": 0o644, "other.log": 0o644,
	} {
		if m := mode(filepath.Join(old, name)); m != want {
			t.Errorf("%s is %04o after a start, want %04o", name, m, want)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(old, "unmask.log")); string(b) != "x\n" {
		t.Errorf("the log that was there was rewritten: %q", b)
	}
}
