package selabel

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
)

// The socket's context is this process's with the type swapped, its file's an
// object of the web server's runtime-file type under the same user, at the low
// end of the range; a range with colons of its own stays whole; anything that
// is not an SELinux context (an AppArmor profile name, nothing at all) is left
// alone, and so is a container's domain.
func TestWebServerContexts(t *testing.T) {
	for _, c := range []struct {
		in, sock, file string
		ok             bool
	}{
		{"system_u:system_r:unconfined_service_t:s0", "system_u:system_r:httpd_t:s0", "system_u:object_r:httpd_var_run_t:s0", true},
		{"system_u:system_r:unconfined_service_t:s0-s0:c0.c1023", "system_u:system_r:httpd_t:s0-s0:c0.c1023", "system_u:object_r:httpd_var_run_t:s0", true},
		{"system_u:system_r:svirt_lxc_net_t:s0:c12,c345", "system_u:system_r:httpd_t:s0:c12,c345", "system_u:object_r:httpd_var_run_t:s0:c12,c345", true},
		{"system_u:system_r:container_t:s0:c12,c345", "", "", false},
		{"system_u:system_r:container_init_t:s0:c1,c2", "", "", false},
		{"system_u:system_r:init_t", "system_u:system_r:httpd_t", "system_u:object_r:httpd_var_run_t", true},
		{"unconfined", "", "", false},
		{"/usr/sbin/unmask (enforce)", "", "", false},
		{"docker-default (enforce)", "", "", false},
		{"kernel", "", "", false},
		{"", "", "", false},
		{"::", "", "", false},
	} {
		sock, file, ok := webServerContexts(c.in)
		if sock != c.sock || file != c.file || ok != c.ok {
			t.Errorf("webServerContexts(%q) = (%q, %q, %v), want (%q, %q, %v)", c.in, sock, file, ok, c.sock, c.file, c.ok)
		}
	}
}

// With or without SELinux, the socket is made and create's own result comes
// back: the label is an extra, never a condition.
func TestForWebServerRunsCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	var conn *net.UnixConn
	_, err := ForWebServer(func() error {
		c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
		conn = c
		return err
	})
	if err != nil || conn == nil {
		t.Fatalf("create under ForWebServer: conn=%v err=%v", conn, err)
	}
	defer conn.Close()
	// The socket made on the thread that has since ended works from this one.
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("a datagram to the socket: %v", err)
	}

	want := errors.New("bind failed")
	if _, err := ForWebServer(func() error { return want }); err != want {
		t.Errorf("create's error = %v, want it passed through", err)
	}
}

// A policy may let the contexts be set and then refuse the socket made under
// them: create is run again without, and that run's result stands.  (Where
// nothing was set -- no SELinux -- there is nothing to take back, and one run
// is all.)
func TestForWebServerFallsBackWithoutTheLabels(t *testing.T) {
	prev := setContexts
	defer func() { setContexts = prev }()

	runs := 0
	setContexts = func(string) (bool, bool) { return true, true }
	labelled, err := ForWebServer(func() error {
		runs++
		if runs == 1 {
			return errors.New("permission denied")
		}
		return nil
	})
	if err != nil || labelled || runs != 2 {
		t.Errorf("refused under the labels: labelled=%v err=%v runs=%d, want unlabelled, nil, 2", labelled, err, runs)
	}

	runs = 0
	setContexts = func(string) (bool, bool) { return true, false }
	labelled, err = ForWebServer(func() error { runs++; return nil })
	if err != nil || !labelled || runs != 1 {
		t.Errorf("made under the labels: labelled=%v err=%v runs=%d, want labelled, nil, 1", labelled, err, runs)
	}

	runs = 0
	setContexts = func(string) (bool, bool) { return false, false }
	want := errors.New("address in use")
	if _, err := ForWebServer(func() error { runs++; return want }); err != want || runs != 1 {
		t.Errorf("nothing set: err=%v runs=%d, want the error from a single run", err, runs)
	}
}
