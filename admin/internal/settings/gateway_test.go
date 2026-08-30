package settings

import (
	"strings"
	"testing"
)

// Every gateway value lands inside a rendered nginx directive, so the
// validation is first of all about what a value must not carry: anything
// that could end the directive and start another.
func TestGatewayValidateRejectsDirectiveBreakers(t *testing.T) {
	base := GatewayConfig{ACMEEmail: "ops@example.test", Certificates: []GatewayCertificate{{Mode: GatewayTLSACME, Domains: "example.test"}}}
	if err := base.Validate(); err != nil {
		t.Fatalf("a plain ACME config must validate: %v", err)
	}
	files := func(domains, cert, key string) []GatewayCertificate {
		return []GatewayCertificate{{Domains: domains, CertPath: cert, KeyPath: key}}
	}
	bad := []GatewayConfig{
		{Hostnames: GatewayHostnames{Mode: GatewayHostsCustom, Names: "example.test; return 200"}, Certificates: files("", "/c", "/k")},
		{Certificates: files("example.test\ninclude /etc/passwd", "/c", "/k")},
		{ACMEEmail: "a@b; }", Certificates: []GatewayCertificate{{Mode: GatewayTLSACME, Domains: "example.test"}}},
		{ACMEEmail: "ops@example.test", ACMEDirectory: "http://plain.example/dir", Certificates: []GatewayCertificate{{Mode: GatewayTLSACME, Domains: "example.test"}}},
		{Certificates: files("example.test", "relative/cert.pem", "/k")},
		{Certificates: files("example.test", "/c.pem", "/k.pem # x")},
		{Certificates: []GatewayCertificate{{ID: "../x", Domains: "example.test"}}},
		{Hostnames: GatewayHostnames{Mode: GatewayHostsCustom}, Certificates: files("", "/c", "/k")},
		{Hostnames: GatewayHostnames{Mode: GatewayHostsCustom, Names: "_"}, Certificates: files("", "/c", "/k")},
		{Hostnames: GatewayHostnames{Mode: GatewayHostsAll}},
	}
	for i, g := range bad {
		if err := g.Validate(); err == nil {
			t.Errorf("case %d: %+v validated; it must not", i, g)
		}
	}
}

// ACME issues for names: it needs domains, and neither "_" nor a wildcard
// can be one.  A mounted file may carry no domains (default only) or a
// wildcard.  The same domain cannot sit on two certificates (nginx would
// warn and pick one).
func TestGatewayValidateACMEDomainsAndDuplicates(t *testing.T) {
	for _, domains := range []string{"", "_", "*.example.test", "shop.example _"} {
		g := GatewayConfig{ACMEEmail: "ops@example.test", Certificates: []GatewayCertificate{{Mode: GatewayTLSACME, Domains: domains}}}
		if err := g.Validate(); err == nil {
			t.Errorf("%q with ACME validated; it must not", domains)
		}
		g.Certificates[0].Mode = GatewayTLSFiles
		g.Certificates[0].CertPath, g.Certificates[0].KeyPath = "/c", "/k"
		err := g.Validate()
		if strings.Contains(domains, "_") {
			if err == nil {
				t.Errorf("%q with files validated; \"_\" is not a domain", domains)
			}
		} else if err != nil {
			t.Errorf("%q with files: %v (a wildcard or no domain is fine with your own certificate)", domains, err)
		}
	}
	g := GatewayConfig{ACMEEmail: "ops@example.test", Certificates: []GatewayCertificate{
		{Mode: GatewayTLSACME, Domains: "shop.example www.shop.example"},
		{ID: "b", Mode: GatewayTLSFiles, Domains: "blog.example", CertPath: "/c", KeyPath: "/k"},
	}}
	if err := g.Validate(); err != nil {
		t.Fatalf("two certificates with different sources must validate: %v", err)
	}
	g.Certificates[1].Domains = "blog.example WWW.shop.example"
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "already on certificate") {
		t.Errorf("a domain on two certificates must be refused, got %v", err)
	}
}

// Hostnames and certificates are independent: a custom hostname no
// certificate names is not an error (the default certificate is served,
// and the tab warns), and a certificate may name domains outside the list.
func TestGatewayUncovered(t *testing.T) {
	g := GatewayConfig{
		Hostnames:    GatewayHostnames{Mode: GatewayHostsCustom, Names: "shop.example www.shop.example blog.example"},
		Certificates: []GatewayCertificate{{Domains: "shop.example other.example", CertPath: "/c", KeyPath: "/k"}},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("uncovered hostnames are a warning, not an error: %v", err)
	}
	if got := strings.Join(g.Uncovered(), " "); got != "www.shop.example blog.example" {
		t.Errorf("Uncovered = %q", got)
	}
	g.Hostnames = GatewayHostnames{Mode: GatewayHostsAll}
	if g.Uncovered() != nil {
		t.Error("with all hostnames nothing is uncovered (the default certificate answers)")
	}
}

// The 0.1.37 single-vhost shape and the 0.1.38 development vhost list fold
// into hostnames + certificates on load, keeping the legacy stored pair (id
// "") and the paths; tls_mode none becomes the gateway-wide "TLS in front".
func TestGatewayNormalizeMigratesEarlierShapes(t *testing.T) {
	g := GatewayConfig{ServerName: " shop.example  www.shop.example ", TLSMode: GatewayTLSUpload, ACMEEmail: "ops@x"}
	g.Normalize()
	if g.HostnamesAll() || g.Hostnames.Names != "shop.example www.shop.example" {
		t.Errorf("migrated hostnames = %+v", g.Hostnames)
	}
	if len(g.Certificates) != 1 || g.Certificates[0].Domains != "shop.example www.shop.example" || g.Certificates[0].ID != "" || g.Certificates[0].ModeResolved() != GatewayTLSUpload {
		t.Errorf("migrated certificates = %+v", g.Certificates)
	}
	if g.ServerName != "" || g.TLSMode != "" || g.Vhosts != nil {
		t.Error("earlier fields must be cleared once folded")
	}
	if g.Certificates[0].CertPathResolved("/etc/unmask") != "/etc/unmask/gateway.crt" {
		t.Errorf("the migrated certificate must keep the legacy stored pair, got %s", g.Certificates[0].CertPathResolved("/etc/unmask"))
	}
	n := GatewayConfig{ServerName: "_", TLSMode: GatewayTLSNone}
	n.Normalize()
	if !n.TLSInFront() || !n.HostnamesAll() || !n.Active() {
		t.Errorf("none migration = %+v", n)
	}
	if err := n.Validate(); err != nil {
		t.Errorf("TLS in front needs no certificate: %v", err)
	}
	if n.UsesACME() {
		t.Error("TLS in front never uses ACME")
	}
	v := GatewayConfig{Vhosts: []GatewayVhost{
		{Names: "shop.example www.shop.example", TLSMode: GatewayTLSACME},
		{ID: "b", Names: "blog.example _", TLSMode: GatewayTLSFiles, CertPath: "/c", KeyPath: "/k"},
	}}
	v.Normalize()
	if !v.HostnamesAll() {
		t.Errorf("a vhost list with a catch-all folds to all hostnames, got %+v", v.Hostnames)
	}
	if len(v.Certificates) != 2 || v.Certificates[0].Domains != "shop.example www.shop.example" || v.Certificates[1].Domains != "blog.example" || v.Certificates[1].ID != "b" {
		t.Errorf("folded certificates = %+v", v.Certificates)
	}
	v = GatewayConfig{Vhosts: []GatewayVhost{{Names: "shop.example", TLSMode: GatewayTLSFiles}}}
	v.Normalize()
	if v.HostnamesAll() || v.Hostnames.Names != "shop.example" {
		t.Errorf("a vhost list without a catch-all folds to the custom list, got %+v", v.Hostnames)
	}
}

// The empty config is "no gateway"; a certificate with nothing set resolves
// to files at the image's default mount paths; a later one has its own
// stored pair.
func TestGatewayDefaults(t *testing.T) {
	var g GatewayConfig
	if g.Active() {
		t.Error("an empty config must not be active")
	}
	if err := g.Validate(); err != nil {
		t.Errorf("an empty config must validate (it is the host-install state): %v", err)
	}
	var c GatewayCertificate
	if c.ModeResolved() != GatewayTLSFiles || c.CertPathResolved("/etc/unmask") != GatewayDefaultCertPath || c.KeyPathResolved("/etc/unmask") != GatewayDefaultKeyPath {
		t.Errorf("empty mode/paths did not resolve to files at the default mount: %+v", c)
	}
	if g.ACMEDirectoryResolved() != ACMEDirectoryLetsEncrypt {
		t.Error("empty directory must resolve to Let's Encrypt production")
	}
	u := GatewayCertificate{ID: "ab12", Mode: GatewayTLSUpload, Domains: "shop.example"}
	if u.CertPathResolved("/etc/unmask") != "/etc/unmask/gateway-ab12.crt" || u.KeyPathResolved("/etc/unmask") != "/etc/unmask/gateway-ab12.key" {
		t.Errorf("upload mode must resolve to the certificate's stored pair, got %s", u.CertPathResolved("/etc/unmask"))
	}
	if u.FirstDomain() != "shop.example" || (GatewayCertificate{Domains: "*.example"}).FirstDomain() != "" {
		t.Error("FirstDomain: the first real domain, none for a wildcard")
	}
	a := GatewayConfig{Certificates: []GatewayCertificate{{CertPath: "/c", KeyPath: "/k"}}}
	a.Normalize()
	if !a.Active() || !a.HostnamesAll() {
		t.Errorf("a certificate alone = an active gateway answering for all hostnames, got %+v", a)
	}
}
