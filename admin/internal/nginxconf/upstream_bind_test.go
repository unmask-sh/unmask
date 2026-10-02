package nginxconf

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// What nginx is told to proxy to, for every way the bind can be written.  An
// IPv6 address goes into `server ...;` in brackets whether or not the config
// has them, and a bind on every interface is reached over loopback.
func TestBuildUpstreamServerFromTheBind(t *testing.T) {
	for _, c := range []struct {
		bind string
		port int
		want string
	}{
		{"127.0.0.1", 9477, "127.0.0.1:9477"},
		{"192.0.2.10", 8765, "192.0.2.10:8765"},
		{"0.0.0.0", 9477, "127.0.0.1:9477"},
		{"", 9477, "127.0.0.1:9477"},
		{"::", 9477, "127.0.0.1:9477"},
		{"[::]", 9477, "127.0.0.1:9477"},
		{"::1", 9477, "[::1]:9477"},
		{"[::1]", 9477, "[::1]:9477"},
		{"2001:db8::10", 0, "[2001:db8::10]:9477"},
		{"unix:/run/unmask/http.sock", 9477, "unix:/run/unmask/http.sock"},
	} {
		s := settings.Settings{Server: settings.Server{Bind: c.bind, Port: c.port}}
		if got := buildUpstreamServer(s); got != c.want {
			t.Errorf("bind %q port %d: upstream %q, want %q", c.bind, c.port, got, c.want)
		}
	}
	// nginx.upstream_addr still wins over anything the bind says.
	s := settings.Settings{Server: settings.Server{Bind: "::", Port: 9477}}
	s.Nginx.UpstreamAddr = "unmask:9477"
	if got := buildUpstreamServer(s); got != "unmask:9477" {
		t.Errorf("upstream_addr override: %q", got)
	}
}
