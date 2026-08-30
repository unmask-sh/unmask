package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The gateway includes exist only while a gateway is configured.  A host
// install must not grow these files.  Each certificate becomes one :443
// server in gateway-vhosts.inc, named by its domains, plus the default
// server; the single-block files (gateway-server.inc, gateway-tls.inc)
// keep describing the first block for the 0.1.37 image.
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

	// All hostnames, two certificates: ACME for the shop names, a mounted
	// pair for the blog.  Three blocks: one per certificate, and the default
	// (any other hostname) serving the first certificate.
	s.Gateway = settings.GatewayConfig{ACMEEmail: "ops@example.test", Certificates: []settings.GatewayCertificate{
		{Mode: settings.GatewayTLSACME, Domains: "example.test www.example.test"},
		{ID: "b", Mode: settings.GatewayTLSFiles, Domains: "blog.example", CertPath: "/certs/a.pem", KeyPath: "/certs/a.key"},
	}}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	vh := read("gateway-vhosts.inc")
	if strings.Count(vh, "server {") != 3 {
		t.Errorf("two certificates + the default must render three server blocks:\n%s", vh)
	}
	for _, want := range []string{
		"server_name example.test www.example.test;", "acme_certificate      unmask_le;", "ssl_certificate       $acme_certificate;",
		"server_name blog.example;", "ssl_certificate     /certs/a.pem;", "ssl_certificate_key /certs/a.key;",
		"listen 443 ssl default_server;", "server_name _;",
		"include /etc/unmask/server.inc;", "include /etc/nginx/unmask-gateway-location.inc;",
	} {
		if !strings.Contains(vh, want) {
			t.Errorf("gateway-vhosts.inc lacks %q", want)
		}
	}
	if strings.Contains(vh, "ssl_reject_handshake") {
		t.Error("with all hostnames nothing is rejected")
	}
	def := vh[strings.Index(vh, "listen 443 ssl default_server;"):]
	if !strings.Contains(def, "acme_certificate      unmask_le;") {
		t.Errorf("the default block must serve the first certificate:\n%s", def)
	}
	if !strings.Contains(read("gateway-server.inc"), "server_name example.test www.example.test;") {
		t.Error("gateway-server.inc must carry the first block's names (0.1.37 image)")
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

	// A custom hostname list: blocks for the listed names only (a domain off
	// the list gets no block), the uncovered name is served the default
	// certificate, and any other Host is refused at the handshake.
	s.Gateway.Hostnames = settings.GatewayHostnames{Mode: settings.GatewayHostsCustom, Names: "example.test blog.example extra.example"}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	vh = read("gateway-vhosts.inc")
	for _, want := range []string{"server_name example.test;", "server_name blog.example;", "server_name extra.example;", "ssl_reject_handshake on;", "listen 443 ssl default_server;"} {
		if !strings.Contains(vh, want) {
			t.Errorf("custom list: gateway-vhosts.inc lacks %q:\n%s", want, vh)
		}
	}
	if strings.Contains(vh, "www.example.test") {
		t.Error("a domain off the hostname list must not get a server block")
	}
	if strings.Count(vh, "server {") != 4 {
		t.Errorf("custom list: expected 4 blocks (2 certificates, uncovered, reject):\n%s", vh)
	}

	// A custom list with a domain-less certificate (a mounted file the admin
	// cannot read): the listed names get the certificate, everything else is
	// rejected -- the names must not fall through to the reject block.
	s.Gateway = settings.GatewayConfig{
		Hostnames:    settings.GatewayHostnames{Mode: settings.GatewayHostsCustom, Names: "localhost"},
		Certificates: []settings.GatewayCertificate{{Mode: settings.GatewayTLSFiles, CertPath: "/certs/a.pem", KeyPath: "/certs/a.key"}},
	}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	vh = read("gateway-vhosts.inc")
	if !strings.Contains(vh, "server_name localhost;") || !strings.Contains(vh, "ssl_certificate     /certs/a.pem;") || strings.Count(vh, "server {") != 2 {
		t.Errorf("a domain-less certificate must serve the custom hostnames:\n%s", vh)
	}

	// Upload mode: the certificate's stored pair under the render directory.
	s.Gateway = settings.GatewayConfig{Certificates: []settings.GatewayCertificate{{ID: "ab12", Mode: settings.GatewayTLSUpload, Domains: "shop.example"}}}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read("gateway-vhosts.inc"), "ssl_certificate     "+filepath.Join(out, "gateway-ab12.crt")+";") {
		t.Errorf("upload mode does not point at the certificate's stored pair:\n%s", read("gateway-vhosts.inc"))
	}
	if strings.Contains(read("gateway-acme.inc"), "acme_issuer") {
		t.Error("no ACME certificate, yet an issuer was rendered")
	}

	// TLS in front: the marker, no server blocks, no certificates.
	s.Gateway = settings.GatewayConfig{TLS: settings.GatewayTLSNone, Hostnames: settings.GatewayHostnames{Mode: settings.GatewayHostsAll}}
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
		t.Error("a 0.1.37 config must render as one certificate for its name")
	}

	// The signature covers the gateway files: a certificate-source change
	// must read as "nginx config changed" (the reload banner keys on it).
	before, _ := RenderSignature(s, out, "test")
	s.Gateway = settings.GatewayConfig{ACMEEmail: "ops@example.test", Certificates: []settings.GatewayCertificate{{Mode: settings.GatewayTLSACME, Domains: "old.example"}}}
	after, _ := RenderSignature(s, out, "test")
	if before == after {
		t.Error("RenderSignature ignores the gateway files")
	}
}
