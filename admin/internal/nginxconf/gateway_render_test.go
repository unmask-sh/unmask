package nginxconf

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
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

	// https only: the :443 blocks as usual, plus the marker that drops :80.
	s.Gateway = settings.GatewayConfig{Listen: []string{"https"}, Certificates: []settings.GatewayCertificate{{Domains: "shop.example", CertPath: "/c.pem", KeyPath: "/k.pem"}}}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	vh = read("gateway-vhosts.inc")
	if !strings.Contains(vh, "# unmask-gateway-http: none") || !strings.Contains(vh, "server_name shop.example;") || strings.Contains(vh, "unmask-gateway-tls: none") {
		t.Errorf("https only must mark the missing :80 and keep :443:\n%s", vh)
	}
	// http only without a trusted load balancer: no https to redirect to,
	// so server.inc carries no redirect even though the setting is on.
	s.Nginx.HTTPSRedirect = true
	s.Gateway = settings.GatewayConfig{Listen: []string{"http"}}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read("server.inc"), "return 301 https://") {
		t.Error("http only with no trusted LB must not redirect to an https that does not exist")
	}
	s.Nginx.TrustedLBPresets = []string{"gcp"}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read("server.inc"), "return 301 https://") {
		t.Error("http only behind a trusted LB keeps the redirect (keyed on X-Forwarded-Proto)")
	}
	s.Nginx.TrustedLBPresets = nil
	s.Nginx.HTTPSRedirect = false

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

// The proxy location is the admin's when an upstream is set in the tab
// (gateway-location.inc), and the trusted proxies are settings > Network's
// trusted LB / CDN set (gateway-proxies.inc); each carries a marker the
// nginx image reads to fall back to its own environment otherwise.
func TestGatewayLocationAndProxiesRender(t *testing.T) {
	out := t.TempDir()
	s, err := settings.LoadFromYAML("")
	if err != nil {
		t.Fatal(err)
	}
	s.Nginx.OutputDir = out
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join(out, n))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		return string(b)
	}
	s.Gateway = settings.GatewayConfig{Certificates: []settings.GatewayCertificate{{CertPath: "/c.pem", KeyPath: "/k.pem"}}}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	if loc := read("gateway-location.inc"); !strings.Contains(loc, "# unmask-gateway-upstream: none") || strings.Contains(loc, "proxy_pass") {
		t.Errorf("no upstream must render the marker and no location:\n%s", loc)
	}
	if prx := read("gateway-proxies.inc"); !strings.Contains(prx, "# unmask-gateway-proxies: none") || strings.Contains(prx, "set_real_ip_from") {
		t.Errorf("no trusted LB must render the marker:\n%s", prx)
	}
	s.Gateway.Upstream = "http://host.docker.internal:8080"
	s.Nginx.TrustedLBPresets = []string{"gcp"}
	s.Nginx.TrustedLBExtra = []settings.TrustedLBExtra{
		{ID: "office", CIDRs: []string{"203.0.113.0/24"}},
		{ID: "old", CIDRs: []string{"198.51.100.0/24"}, Disabled: true},
	}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	loc := read("gateway-location.inc")
	for _, want := range []string{"location / {", "include /etc/unmask/protect.inc;", "proxy_pass http://host.docker.internal:8080;", "proxy_set_header X-Forwarded-Proto $unmask_gw_xfp;", "proxy_set_header Connection        $connection_upgrade;"} {
		if !strings.Contains(loc, want) {
			t.Errorf("gateway-location.inc lacks %q:\n%s", want, loc)
		}
	}
	if strings.Contains(loc, "unmask-gateway-upstream: none") {
		t.Error("the none marker must go once an upstream is set")
	}
	prx := read("gateway-proxies.inc")
	for _, want := range []string{"set_real_ip_from 130.211.0.0/22;", "set_real_ip_from 35.191.0.0/16;", "set_real_ip_from 203.0.113.0/24;", "real_ip_header X-Forwarded-For;", "real_ip_recursive on;"} {
		if !strings.Contains(prx, want) {
			t.Errorf("gateway-proxies.inc lacks %q:\n%s", want, prx)
		}
	}
	if strings.Contains(prx, "198.51.100.0/24") {
		t.Error("a disabled custom LB row must not be trusted")
	}
	// TLS in front still needs the location (:80 proxies too).
	s.Gateway.TLS = settings.GatewayTLSNone
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read("gateway-location.inc"), "proxy_pass http://host.docker.internal:8080;") {
		t.Error("TLS in front must still render the proxy location")
	}
}

// A self-signed entry's pair is generated by the render -- with the names
// it should carry -- kept while nothing changes, and regenerated when the
// names change.  A pasted pair stored under the same id is never touched.
func TestGatewaySelfSignedGenerated(t *testing.T) {
	out := t.TempDir()
	s, err := settings.LoadFromYAML("")
	if err != nil {
		t.Fatal(err)
	}
	s.Nginx.OutputDir = out
	s.Gateway = settings.GatewayConfig{Certificates: []settings.GatewayCertificate{{Mode: settings.GatewayTLSSelfSigned}}}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(out, "gateway.crt"), filepath.Join(out, "gateway.key")
	first, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("no certificate generated: %v", err)
	}
	if ki, err := os.Stat(keyPath); err != nil || ki.Mode().Perm() != 0o600 {
		t.Errorf("key: %v / mode %v (want 0600)", err, ki)
	}
	leaf, err := parseTestCert(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(leaf.DNSNames, " ") != "localhost" || leaf.Subject.CommonName != "localhost" || leaf.Subject.Organization[0] != selfSignedOrg {
		t.Errorf("generated certificate = CN %q SAN %v O %v", leaf.Subject.CommonName, leaf.DNSNames, leaf.Subject.Organization)
	}
	vh, _ := os.ReadFile(filepath.Join(out, "gateway-vhosts.inc"))
	if !strings.Contains(string(vh), "ssl_certificate     "+certPath+";") {
		t.Errorf("the vhosts must name the generated pair:\n%s", vh)
	}
	// Unchanged names: the same file.
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(certPath); string(again) != string(first) {
		t.Error("a second render regenerated an unchanged certificate")
	}
	// The hostnames change: regenerated with them.
	s.Gateway.Hostnames = settings.GatewayHostnames{Mode: settings.GatewayHostsCustom, Names: "shop.example www.shop.example"}
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(certPath)
	leaf, _ = parseTestCert(second)
	if string(second) == string(first) || strings.Join(leaf.DNSNames, " ") != "shop.example www.shop.example" {
		t.Errorf("changed names must regenerate: SAN %v", leaf.DNSNames)
	}
	// A pasted pair (not ours) under the same id is left alone.
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nnot ours\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Gateway.Certificates[0].Mode = settings.GatewayTLSUpload
	if err := Render(s, out, "test"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(certPath); !strings.Contains(string(b), "not ours") {
		t.Error("an upload entry's stored pair was overwritten by the self-signed generator")
	}
}

func parseTestCert(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}
