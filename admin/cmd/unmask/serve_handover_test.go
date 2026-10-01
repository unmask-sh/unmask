package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxlog"
)

// A serve that cannot load its config ends before the log receiver is up.  On
// its way out it takes the log socket's name out of the service manager's
// store (nginxlog/handover.go): systemd would hand a kept socket to every
// retry otherwise, and nginx would log into it unread for as long as the
// retries fail.
func TestServeThatFailsEarlyLeavesNoKeptSocket(t *testing.T) {
	dir := t.TempDir()
	notify := filepath.Join(dir, "notify")
	mgr, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notify, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	t.Setenv("NOTIFY_SOCKET", notify)
	t.Setenv(nginxlog.HandoverEnv, "1")
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		t.Setenv(k, "")
	}
	cfg := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfg, []byte("server: [this is not yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cmdServe([]string{"-config", cfg}); err == nil {
		t.Fatal("serve went on with a config that does not parse")
	}
	buf := make([]byte, 256)
	_ = mgr.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := mgr.Read(buf)
	if err != nil {
		t.Fatalf("nothing was said to the service manager: %v", err)
	}
	if got, want := string(buf[:n]), "FDSTOREREMOVE=1\nFDNAME=nginxlog"; got != want {
		t.Errorf("said %q, want %q", got, want)
	}

	// Without the drop-in there is no store, and nothing to say.
	t.Setenv(nginxlog.HandoverEnv, "")
	if err := cmdServe([]string{"-config", cfg}); err == nil {
		t.Fatal("serve went on with a config that does not parse")
	}
	_ = mgr.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := mgr.Read(buf); err == nil {
		t.Errorf("said %q without the drop-in", string(buf[:n]))
	}
}
