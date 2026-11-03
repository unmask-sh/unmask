package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// doctor reads the access-log socket's mode: shared by group is fine, open
// to every local user is a warning that names the setting, and no socket
// (the daemon is not running, the receiver is off) is nothing to say.
func TestDoctorLogSocketShare(t *testing.T) {
	dir, err := os.MkdirTemp("", "dls")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "log.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	run := func(s settings.Settings) (oks, warns []string) {
		checkLogSocketShare(s,
			func(_, m string) { oks = append(oks, m) },
			func(_, m string) { warns = append(warns, m) })
		return
	}
	on := settings.Settings{NginxLog: settings.NginxLog{Enabled: true, SocketPath: path}}

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	oks, warns := run(on)
	if len(oks) != 0 || len(warns) != 1 || !strings.Contains(warns[0], "0666") || !strings.Contains(warns[0], "nginx_log.socket_group") {
		t.Errorf("world-writable socket: ok=%v warn=%v", oks, warns)
	}

	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	oks, warns = run(on)
	if len(oks) != 1 || len(warns) != 0 || !strings.Contains(oks[0], "0660") {
		t.Errorf("group-shared socket: ok=%v warn=%v", oks, warns)
	}

	off := on
	off.NginxLog.Enabled = false
	if oks, warns = run(off); len(oks)+len(warns) != 0 {
		t.Errorf("receiver off: ok=%v warn=%v", oks, warns)
	}
	gone := on
	gone.NginxLog.SocketPath = filepath.Join(dir, "none.sock")
	if oks, warns = run(gone); len(oks)+len(warns) != 0 {
		t.Errorf("no socket: ok=%v warn=%v", oks, warns)
	}
}
