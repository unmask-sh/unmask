package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The settings page takes "::" for the bind, and the daemon then joined it to
// the port as ":::9477": it did not come back from its next restart.  Every
// way an address can be written has to listen, and be reachable.
func TestOpenListenerTakesEveryFormOfAddress(t *testing.T) {
	binds := []string{"127.0.0.1", "0.0.0.0"}
	if probe, err := net.Listen("tcp", "[::1]:0"); err == nil {
		_ = probe.Close()
		binds = append(binds, "::", "[::]", "::1", "[::1]")
	} else {
		t.Logf("no IPv6 loopback here (%v): the IPv6 forms are not tried", err)
	}
	for _, bind := range binds {
		ln, shown, err := openListener(settings.Server{Bind: bind, Port: 0})
		if err != nil {
			t.Errorf("bind %q does not listen: %v", bind, err)
			continue
		}
		c, derr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if derr != nil {
			t.Errorf("bind %q listens on %s (shown as %q) but cannot be reached: %v", bind, ln.Addr(), shown, derr)
		} else {
			_ = c.Close()
		}
		_ = ln.Close()
	}
}

// A bind with the port in it is what an older post-install message told the
// operator to write.  It cannot listen; the error has to say what to write
// instead, not "too many colons in address".
func TestOpenListenerSaysWhereThePortGoes(t *testing.T) {
	for _, bind := range []string{"0.0.0.0:9477", "127.0.0.1:9477", "[::]:9477"} {
		ln, _, err := openListener(settings.Server{Bind: bind, Port: 9477})
		if err == nil {
			_ = ln.Close()
			t.Errorf("bind %q listened; it carries a port and must be refused", bind)
			continue
		}
		if !strings.Contains(err.Error(), "server.port") || strings.Contains(err.Error(), "too many colons") {
			t.Errorf("bind %q: the error does not say where the port goes: %v", bind, err)
		}
	}
}

// The CLI dials, and the doctor asks, the address the daemon listens on.
func TestDialAndSelfCheckFollowTheBind(t *testing.T) {
	for _, c := range []struct{ bind, dial, url string }{
		{"127.0.0.1", "127.0.0.1:9477", "http://127.0.0.1:9477/unmask/healthz"},
		{"", "127.0.0.1:9477", "http://127.0.0.1:9477/unmask/healthz"},
		{"0.0.0.0", "0.0.0.0:9477", "http://127.0.0.1:9477/unmask/healthz"},
		{"::", "[::]:9477", "http://127.0.0.1:9477/unmask/healthz"},
		{"[::]", "[::]:9477", "http://127.0.0.1:9477/unmask/healthz"},
		{"::1", "[::1]:9477", "http://[::1]:9477/unmask/healthz"},
		{"[::1]", "[::1]:9477", "http://[::1]:9477/unmask/healthz"},
	} {
		srv := settings.Server{Bind: c.bind, Port: 9477, BasePath: "/unmask"}
		if network, addr := daemonDial(srv); network != "tcp" || addr != c.dial {
			t.Errorf("bind %q: dial target %s %q, want tcp %q", c.bind, network, addr, c.dial)
		}
		if url, _ := sloTarget(srv); url != c.url {
			t.Errorf("bind %q: self-check URL %q, want %q", c.bind, url, c.url)
		}
	}
}
