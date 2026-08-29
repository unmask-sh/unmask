package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The gateway includes exist only while a gateway is configured, and say
// exactly one thing each: the vhost name, the certificate source, the ACME
// issuer (or nothing).  A host install must not grow these files.
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

	s.Gateway = settings.GatewayConfig{ServerName: "example.test", TLSMode: settings.GatewayTLSACME, ACMEEmail: "ops@example.test"}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join(out, n))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		return string(b)
	}
	if !strings.Contains(read("gateway-server.inc"), "server_name example.test;") {
		t.Error("gateway-server.inc does not carry the vhost name")
	}
	tls := read("gateway-tls.inc")
	for _, want := range []string{"acme_certificate      unmask_le;", "ssl_certificate       $acme_certificate;", "ssl_certificate_key   $acme_certificate_key;"} {
		if !strings.Contains(tls, want) {
			t.Errorf("gateway-tls.inc (acme) lacks %q", want)
		}
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

	// Files mode: paths in, issuer out.
	s.Gateway = settings.GatewayConfig{ServerName: "_", TLSMode: settings.GatewayTLSFiles, TLSCertPath: "/certs/a.pem", TLSKeyPath: "/certs/a.key"}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	tls = read("gateway-tls.inc")
	if !strings.Contains(tls, "ssl_certificate     /certs/a.pem;") || !strings.Contains(tls, "ssl_certificate_key /certs/a.key;") {
		t.Errorf("gateway-tls.inc (files) does not point at the given files:\n%s", tls)
	}
	if strings.Contains(tls, "acme_certificate") {
		t.Error("files mode still references the ACME certificate")
	}
	if strings.Contains(read("gateway-acme.inc"), "acme_issuer") {
		t.Error("files mode still renders an ACME issuer")
	}

	// Upload mode: the stored pair under the render directory.
	s.Gateway = settings.GatewayConfig{ServerName: "shop.example", TLSMode: settings.GatewayTLSUpload}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	tls = read("gateway-tls.inc")
	if !strings.Contains(tls, "ssl_certificate     "+filepath.Join(out, "gateway.crt")+";") {
		t.Errorf("upload mode does not point at the stored certificate:\n%s", tls)
	}

	// The signature covers the gateway files: a certificate-source change
	// must read as "nginx config changed" (the reload banner keys on it).
	before, _ := RenderSignature(s, out, "test")
	s.Gateway.TLSMode = settings.GatewayTLSACME
	s.Gateway.ACMEEmail = "ops@example.test"
	after, _ := RenderSignature(s, out, "test")
	if before == after {
		t.Error("RenderSignature ignores the gateway files")
	}
}
