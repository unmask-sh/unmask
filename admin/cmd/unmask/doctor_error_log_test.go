package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanNginxErrorLog picks out the uninitialized-variable warning (per
// variable, with the last line) and the fatal-severity lines; ordinary
// [error] / [notice] lines are not counted.
func TestScanNginxErrorLog(t *testing.T) {
	log := `2026/09/05 21:12:22 [warn] 79#79: *440 using uninitialized "unmask_failopen" variable, client: 35.191.222.245, server: _, request: "GET /api/myip/ HTTP/1.1"
2026/09/05 21:12:23 [warn] 79#79: *441 using uninitialized "unmask_failopen" variable, client: 35.191.222.246, server: _, request: "GET /api/myip/ HTTP/1.1"
2026/09/05 21:12:24 [error] 79#79: *442 connect() failed (111: Connection refused) while connecting to upstream
2026/09/05 21:13:00 [notice] 1#1: signal process started
2026/09/05 21:14:00 [emerg] 1#1: unknown directive "unmask_nope" in /etc/nginx/conf.d/x.conf:3
`
	rep := scanNginxErrorLog(strings.NewReader(log))
	if rep.Lines != 5 || len(rep.Uninit) != 1 || rep.Uninit["unmask_failopen"] != 2 || !strings.Contains(rep.UninitLast, "*441") {
		t.Errorf("uninit: %+v", rep)
	}
	if rep.Fatal != 1 || !strings.Contains(rep.FatalLast, "unknown directive") {
		t.Errorf("fatal: %+v", rep)
	}
}

// checkNginxErrorLog: a clean tail is OK, a warning-bearing one is a WARN
// that names the variable, an [emerg] is a WARN of its own, and a path that
// cannot be read is silent.
func TestCheckNginxErrorLog(t *testing.T) {
	dir := t.TempDir()
	old := nginxErrorLogFile
	t.Cleanup(func() { nginxErrorLogFile = old })
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	nginxErrorLogFile = write("clean.log", "2026/09/05 21:13:00 [notice] 1#1: signal process started\n")
	cap, addOK, addWarn, _ := newCaptures()
	checkNginxErrorLog(addOK, addWarn)
	if len(cap.ok) != 1 || len(cap.warn) != 0 {
		t.Errorf("clean: ok=%v warn=%v", cap.ok, cap.warn)
	}

	nginxErrorLogFile = write("warn.log", `2026/09/05 21:12:22 [warn] 79#79: *440 using uninitialized "unmask_failopen" variable, client: 35.191.222.245`+"\n"+
		`2026/09/05 21:14:00 [emerg] 1#1: unknown directive "unmask_nope" in /etc/nginx/conf.d/x.conf:3`+"\n")
	cap, addOK, addWarn, _ = newCaptures()
	checkNginxErrorLog(addOK, addWarn)
	if len(cap.ok) != 0 || len(cap.warn) != 2 || !strings.Contains(fmt.Sprint(cap.warn[0]), "$unmask_failopen x1") || !strings.Contains(fmt.Sprint(cap.warn[1]), "unknown directive") {
		t.Errorf("warn: ok=%v warn=%v", cap.ok, cap.warn)
	}

	nginxErrorLogFile = filepath.Join(dir, "missing.log")
	cap, addOK, addWarn, _ = newCaptures()
	checkNginxErrorLog(addOK, addWarn)
	if len(cap.ok)+len(cap.warn) != 0 {
		t.Errorf("missing: ok=%v warn=%v", cap.ok, cap.warn)
	}

	// Present but not readable (the packaged 0640 nginx:adm, read as the
	// daemon user): a WARN that names a command which works, not silence.
	if os.Geteuid() != 0 {
		nginxErrorLogFile = write("locked.log", "x\n")
		if err := os.Chmod(nginxErrorLogFile, 0o000); err != nil {
			t.Fatal(err)
		}
		cap, addOK, addWarn, _ = newCaptures()
		checkNginxErrorLog(addOK, addWarn)
		if len(cap.ok) != 0 || len(cap.warn) != 1 || !strings.Contains(fmt.Sprint(cap.warn[0]), "sudo grep -c") {
			t.Errorf("unreadable: ok=%v warn=%v", cap.ok, cap.warn)
		}
	}
}
