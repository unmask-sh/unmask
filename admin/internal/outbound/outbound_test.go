package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRefuse(t *testing.T) {
	cases := []struct {
		addr   string
		policy Policy
		local  bool
		want   string // "" = allowed, else a word of the reason
	}{
		// The metadata addresses, under every policy.
		{"169.254.169.254", Policy{}, false, "metadata"},
		{"169.254.169.254", Policy{AllowLoopback: true}, true, "metadata"},
		{"169.254.170.2", Policy{}, false, "metadata"},
		{"fd00:ec2::254", Policy{}, false, "metadata"},
		{"fe80::1", Policy{}, false, "metadata"},
		{"100.100.100.200", Policy{}, false, "metadata"},
		{"::ffff:169.254.169.254", Policy{}, false, "metadata"},
		{"64:ff9b::a9fe:a9fe", Policy{}, false, "metadata"}, // NAT64 of 169.254.169.254
		// Loopback: refused by default, open to a local-by-design caller
		// or by the operator.
		{"127.0.0.1", Policy{}, false, "loopback"},
		{"127.0.0.53", Policy{}, false, "loopback"},
		{"::1", Policy{}, false, "loopback"},
		{"::ffff:127.0.0.1", Policy{}, false, "loopback"},
		{"127.0.0.1", Policy{}, true, ""},
		{"::1", Policy{AllowLoopback: true}, false, ""},
		// Private networks: allowed unless the operator shuts them.
		{"10.1.2.3", Policy{}, false, ""},
		{"192.168.1.10", Policy{}, false, ""},
		{"172.16.0.9", Policy{}, false, ""},
		{"fd12::1", Policy{}, false, ""},
		{"100.64.0.1", Policy{}, false, ""},
		{"10.1.2.3", Policy{DenyPrivate: true}, false, "private"},
		{"192.168.1.10", Policy{DenyPrivate: true}, false, "private"},
		{"fd12::1", Policy{DenyPrivate: true}, false, "private"},
		{"100.64.0.1", Policy{DenyPrivate: true}, false, "private"},
		// deny_private does not touch loopback: a local-by-design caller
		// still reaches its relay on the host.
		{"127.0.0.1", Policy{DenyPrivate: true}, true, ""},
		// Not addresses to connect to at all.
		{"0.0.0.0", Policy{}, false, "not an address"},
		{"::", Policy{}, false, "not an address"},
		{"224.0.0.1", Policy{}, false, "unicast"},
		{"255.255.255.255", Policy{}, false, "unicast"},
		// Public addresses pass.
		{"203.0.113.9", Policy{DenyPrivate: true}, false, ""},
		{"2001:db8::9", Policy{DenyPrivate: true}, false, ""},
	}
	for _, c := range cases {
		got := c.policy.Refuse(netip.MustParseAddr(c.addr), c.local)
		switch {
		case c.want == "" && got != "":
			t.Errorf("%s under %+v (local=%v): refused: %s", c.addr, c.policy, c.local, got)
		case c.want != "" && !strings.Contains(got, c.want):
			t.Errorf("%s under %+v (local=%v): reason %q, want one about %q", c.addr, c.policy, c.local, got, c.want)
		}
	}
}

// The judgement is made on the address the connection is about to be made
// to: a listener on loopback is refused whether it is named by address or
// by a name that resolves to it, and reached by the local-by-design client
// or once the operator opens loopback.
func TestDialJudgesTheResolvedAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	t.Cleanup(func() { SetPolicy(Policy{}) })
	SetPolicy(Policy{})

	refused := func(t *testing.T, c *http.Client, url string) {
		t.Helper()
		resp, err := c.Get(url)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("GET %s went through", url)
		}
		var oe *Error
		if !errors.As(err, &oe) {
			t.Fatalf("GET %s: %v, want the policy's refusal", url, err)
		}
		if !oe.Addr.IsLoopback() {
			t.Errorf("refusal names %s, want the loopback address", oe.Addr)
		}
	}
	ok := func(t *testing.T, c *http.Client, url string) {
		t.Helper()
		resp, err := c.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		resp.Body.Close()
	}

	refused(t, Client(2*time.Second), srv.URL)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	// By name: the refusal comes after resolution, so a name pointing at the
	// host (rebinding) ends the same way.
	refused(t, Client(2*time.Second), "http://localhost:"+port+"/")
	ok(t, LocalClient(2*time.Second), srv.URL)
	SetPolicy(Policy{AllowLoopback: true})
	ok(t, Client(2*time.Second), srv.URL)
	// A redirect is a new dial, judged again.
	SetPolicy(Policy{})
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound)
	}))
	defer redir.Close()
	refused(t, LocalClientRedirectingTo(t, redir), redir.URL)
}

// LocalClientRedirectingTo is a local-by-design client whose redirects are
// judged under the default policy: the first hop is allowed (local), the
// hop the server redirects to is dialed under the policy of a plain client.
func LocalClientRedirectingTo(t *testing.T, redir *httptest.Server) *http.Client {
	t.Helper()
	c := Client(2 * time.Second)
	first := true
	c.Transport = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if first {
			first = false
			return Dialer(2*time.Second, true).DialContext(ctx, network, addr)
		}
		return DialContext(ctx, network, addr)
	}}
	return c
}

// Unix sockets have no address to judge, and the policy leaves them alone.
func TestUnixSocketsPassTheControlHook(t *testing.T) {
	if err := control(false)("unix", "/run/unmask/admin.sock", nil); err != nil {
		t.Fatalf("unix: %v", err)
	}
	if err := control(false)("tcp", "169.254.169.254:80", nil); err == nil {
		t.Fatal("tcp to the metadata address passed")
	}
}
