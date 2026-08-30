package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The gateway includes exist only while a gateway is configured.  A host
// install must not grow these files.  Each vhost becomes one :443 server in
// gateway-vhosts.inc; the single-block files (gateway-server.inc,
// gateway-tls.inc) keep describing the first vhost for the 0.1.37 image.
func TestGatewayIncludesRenderOnlyWhenConfigured(t *testing.T) {
	out := t.TempDir()
	s, err := settings.LoadFromYAML("")
	if err != nil {
		t.Fatal(err)
	}
	s.Nginx.OutputDir = out

	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	for _, gt := range gatewayTemplates {
		if _, err := os.Stat(filepath.Join(out, gt[0])); err == nil {
			t.Errorf("%s rendered with no gateway configured; a host install must not get it", gt[0])
		}
	}
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join(out, n))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		return string(b)
	}

	// Two vhosts: ACME for the named one, a mounted pair for the catch-all,
	// which is the default server whatever its position.
	s.Gateway = settings.GatewayConfig{ACMEEmail: "ops@example.test", Vhosts: []settings.GatewayVhost{
		{Names: "example.test www.example.test", TLSMode: settings.GatewayTLSACME},
		{ID: "b", Names: "_", TLSMode: settings.GatewayTLSFiles, CertPath: "/certs/a.pem", KeyPath: "/certs/a.key"},
	}}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	vh := read("gateway-vhosts.inc")
	if strings.Count(vh, "server {") != 2 {
		t.Errorf("two vhosts must render two server blocks:\n%s", vh)
	}
	for _, want := range []string{
		"server_name example.test www.example.test;", "acme_certificate      unmask_le;", "ssl_certificate       $acme_certificate;",
		"listen 443 ssl default_server;", "server_name _;", "ssl_certificate     /certs/a.pem;", "ssl_certificate_key /certs/a.key;",
		"include /etc/unmask/server.inc;", "include /etc/nginx/unmask-gateway-location.inc;",
	} {
		if !strings.Contains(vh, want) {
			t.Errorf("gateway-vhosts.inc lacks %q", want)
		}
	}
	if strings.Contains(vh, "listen 443 ssl;\n    listen [::]:443 ssl;\n    http2 on;\n    server_name _;") {
		t.Error("the catch-all vhost must be the default server")
	}
	if !strings.Contains(read("gateway-server.inc"), "server_name example.test www.example.test;") {
		t.Error("gateway-server.inc must carry the first vhost's names (0.1.37 image)")
	}
	acme := read("gateway-acme.inc")
	for _, want := range []string{"acme_issuer unmask_le {", "uri         " + settings.ACMEDirectoryLetsEncrypt + ";", "contact     mailto:ops@example.test;", "ssl_verify  on;", "state_path  /var/cache/nginx/unmask-acme;"} {
		if !strings.Contains(acme, want) {
			t.Errorf("gateway-acme.inc lacks %q", want)
		}
	}
	for _, line := range strings.Split(acme, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "resolver") {
			t.Error("the resolver belongs to the nginx container (it knows its nameservers); the admin must not render one")
		}
	}

	// Upload mode: the row's stored pair under the render directory.
	s.Gateway = settings.GatewayConfig{Vhosts: []settings.GatewayVhost{{ID: "ab12", Names: "shop.example", TLSMode: settings.GatewayTLSUpload}}}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read("gateway-vhosts.inc"), "ssl_certificate     "+filepath.Join(out, "gateway-ab12.crt")+";") {
		t.Errorf("upload mode does not point at the row's stored certificate:\n%s", read("gateway-vhosts.inc"))
	}
	if strings.Contains(read("gateway-acme.inc"), "acme_issuer") {
		t.Error("no ACME vhost, yet an issuer was rendered")
	}

	// TLS in front: the marker, no server blocks, no certificates.
	s.Gateway = settings.GatewayConfig{TLS: settings.GatewayTLSNone, Vhosts: []settings.GatewayVhost{{Names: "shop.example www.shop.example"}}}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	vh = read("gateway-vhosts.inc")
	if !strings.Contains(vh, "# unmask-gateway-tls: none") || strings.Contains(vh, "server {") || strings.Contains(vh, "ssl_certificate") {
		t.Errorf("TLS in front must render the marker and nothing to listen on:\n%s", vh)
	}
	if !strings.Contains(read("gateway-tls.inc"), "# unmask-gateway-tls: none") {
		t.Error("gateway-tls.inc must carry the marker too (0.1.37 image)")
	}

	// The 0.1.37 single-vhost config still renders (migration on load).
	s.Gateway = settings.GatewayConfig{ServerName: "old.example", TLSMode: settings.GatewayTLSFiles, TLSCertPath: "/c.pem", TLSKeyPath: "/k.pem"}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read("gateway-vhosts.inc"), "server_name old.example;") || !strings.Contains(read("gateway-tls.inc"), "ssl_certificate     /c.pem;") {
		t.Error("a 0.1.37 config must render as one vhost")
	}

	// The signature covers the gateway files: a certificate-source change
	// must read as "nginx config changed" (the reload banner keys on it).
	before, _ := RenderSignature(s, out, "test")
	s.Gateway = settings.GatewayConfig{ACMEEmail: "ops@example.test", Vhosts: []settings.GatewayVhost{{Names: "old.example", TLSMode: settings.GatewayTLSACME}}}
	after, _ := RenderSignature(s, out, "test")
	if before == after {
		t.Error("RenderSignature ignores the gateway files")
	}
}
