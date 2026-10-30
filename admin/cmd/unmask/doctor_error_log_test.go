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
2026/09/05 21:15:00 [warn] 79#79: *450 unmask: no JA4 for a TLS connection: the ClientHello never reached this module's callback. Another module that calls SSL_CTX_set_msg_callback on the same server replaces it (one callback per SSL_CTX), so JA4-based decisions do not apply; load one of the two, or report which module it is, client: 203.0.113.9, server: _, request: "GET / HTTP/1.1"
`
	rep := scanNginxErrorLog(strings.NewReader(log))
	if rep.Lines != 6 || len(rep.Uninit) != 1 || rep.Uninit["unmask_failopen"] != 2 || !strings.Contains(rep.UninitLast, "*441") {
		t.Errorf("uninit: %+v", rep)
	}
	if rep.Fatal != 1 || !strings.Contains(rep.FatalLast, "unknown directive") {
		t.Errorf("fatal: %+v", rep)
	}
	// The module's own warning that its TLS callback was replaced: counted
	// apart from the fatal lines, with the last one kept.
	if rep.NoJA4 != 1 || !strings.Contains(rep.NoJA4Last, "*450") {
		t.Errorf("no-JA4: %+v", rep)
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

// The Lua module built against a LuaJIT other than OpenResty's writes an
// [alert] at every configuration load: on such a host the tail always holds
// one, so it is left out (and said so), while a real fatal line beside it is
// still reported -- whole enough to read past its timestamp and pid.
func TestNginxErrorLogLuaJITNotice(t *testing.T) {
	dir := t.TempDir()
	old := nginxErrorLogFile
	t.Cleanup(func() { nginxErrorLogFile = old })
	luajit := `2026/10/13 14:37:28 [alert] 1234#1234: detected a LuaJIT version which is not OpenResty's; many optimizations will be disabled and performance and stability may suffer (please use OpenResty's LuaJIT 2.1 for optimal performance and stability)`

	nginxErrorLogFile = filepath.Join(dir, "lua.log")
	if err := os.WriteFile(nginxErrorLogFile, []byte(luajit+"\n"+luajit+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cap, addOK, addWarn, _ := newCaptures()
	checkNginxErrorLog(addOK, addWarn)
	if len(cap.warn) != 0 || len(cap.ok) != 1 || !strings.Contains(fmt.Sprint(cap.ok[0]), "2 [alert] line(s) of the Lua module's LuaJIT notice") {
		t.Errorf("LuaJIT notice only: ok=%v warn=%v", cap.ok, cap.warn)
	}

	emerg := `2026/10/13 14:52:10 [emerg] 1#1: unknown directive "unmask_nope" in /etc/nginx/conf.d/x.conf:3`
	if err := os.WriteFile(nginxErrorLogFile, []byte(emerg+"\n"+luajit+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cap, addOK, addWarn, _ = newCaptures()
	checkNginxErrorLog(addOK, addWarn)
	if len(cap.ok) != 0 || len(cap.warn) != 1 || !strings.Contains(fmt.Sprint(cap.warn[0]), "1 [emerg]/[crit]/[alert] line(s)") ||
		!strings.Contains(fmt.Sprint(cap.warn[0]), "/etc/nginx/conf.d/x.conf:3") {
		t.Errorf("a real [emerg] beside the notice: ok=%v warn=%v", cap.ok, cap.warn)
	}
}
