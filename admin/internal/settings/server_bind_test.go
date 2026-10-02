package settings

import "testing"

// The bind is joined to a port in four places: the listener, nginx's upstream,
// the CLI's dial target and the doctor's self-check.  Each takes the host from
// here, so an IPv6 bind reads the same to all of them whether it was written
// bare or in brackets.
func TestServerTCPHost(t *testing.T) {
	for _, c := range []struct{ bind, want string }{
		{"127.0.0.1", "127.0.0.1"},
		{"0.0.0.0", "0.0.0.0"},
		{"::", "::"},
		{"[::]", "::"},
		{"::1", "::1"},
		{"[::1]", "::1"},
		{" [2001:db8::10] ", "2001:db8::10"},
		{"", ""},
		{"unix:/run/unmask/http.sock", ""},
	} {
		if got := (Server{Bind: c.bind}).TCPHost(); got != c.want {
			t.Errorf("TCPHost(%q) = %q, want %q", c.bind, got, c.want)
		}
	}
}
