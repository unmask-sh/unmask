package nginxconf

import (
	"strings"
	"testing"
)

// A load balancer that terminates TLS commonly forwards X-Forwarded-Proto but
// no X-Forwarded-Port (GCP's HTTP(S) LB does exactly this).  The port map then
// fell back to $server_port -- the port the LB used to reach THIS nginx, 80 --
// and the event was recorded as "80 (https)", a combination no visitor used
// (measured: 3.1M such events on one fleet node).  The fallback now takes the
// forwarded scheme's default port whenever a proto was forwarded, and keeps
// $server_port only for requests nobody proxied, where the listener is the
// truth.  server.inc also forwards the accepted port so the inference stays
// auditable in the hunt popover.
func TestForwardedPortFallsBackToTheSchemeDefault(t *testing.T) {
	inc := renderHTTPInc(t, nil)
	for _, want := range []string{
		// scheme -> its default port
		`map $unmask_forwarded_proto $unmask_default_port {`,
		`https   443;`,
		// a forwarded request takes that default; an unproxied one keeps the listener
		`map $http_x_forwarded_proto $unmask_port_fallback {`,
		`default       $server_port;`,
		`"~."          $unmask_default_port;`,
		// the LB's own header still wins when it sends one
		`map $http_x_forwarded_port $unmask_forwarded_port {`,
		`default       $unmask_port_fallback;`,
		`"~^[1-9][0-9]{0,4}$" $http_x_forwarded_port;`,
	} {
		if !strings.Contains(inc, want) {
			t.Errorf("http.inc is missing %q", want)
		}
	}
	// The old fallback would re-introduce the "80 (https)" rows.
	if strings.Contains(inc, "map $http_x_forwarded_port $unmask_forwarded_port {\n    default       $server_port;") {
		t.Error("the port map still falls straight back to $server_port behind an LB")
	}
}
