package settings

import (
	"strings"
	"testing"
)

// Every gateway value lands inside a rendered nginx directive, so the
// validation is first of all about what a value must not carry: anything
// that could end the directive and start another.
func TestGatewayValidateRejectsDirectiveBreakers(t *testing.T) {
	base := GatewayConfig{ACMEEmail: "ops@example.test", Vhosts: []GatewayVhost{{Names: "example.test", TLSMode: GatewayTLSACME}}}
	if err := base.Validate(); err != nil {
		t.Fatalf("a plain ACME config must validate: %v", err)
	}
	bad := []GatewayConfig{
		{Vhosts: []GatewayVhost{{Names: "example.test; return 200"}}},
		{Vhosts: []GatewayVhost{{Names: "example.test\ninclude /etc/passwd"}}},
		{ACMEEmail: "a@b; }", Vhosts: []GatewayVhost{{Names: "example.test", TLSMode: GatewayTLSACME}}},
		{ACMEEmail: "ops@example.test", ACMEDirectory: "http://plain.example/dir", Vhosts: []GatewayVhost{{Names: "example.test", TLSMode: GatewayTLSACME}}},
		{Vhosts: []GatewayVhost{{Names: "example.test", CertPath: "relative/cert.pem", KeyPath: "/k"}}},
		{Vhosts: []GatewayVhost{{Names: "example.test", CertPath: "/c.pem", KeyPath: "/k.pem # x"}}},
		{Vhosts: []GatewayVhost{{ID: "../x", Names: "example.test"}}},
	}
	for i, g := range bad {
		if err := g.Validate(); err == nil {
			t.Errorf("case %d: %+v validated; it must not", i, g)
		}
	}
}

// ACME issues for names: a catch-all or a wildcard cannot be its subject,
// and every name of a vhost is checked.  The same name cannot be served by
// two vhosts (nginx would warn and pick one).
func TestGatewayValidateACMENamesAndDuplicates(t *testing.T) {
	for _, names := range []string{"_", "*.example.test", "shop.example _"} {
		g := GatewayConfig{ACMEEmail: "ops@example.test", Vhosts: []GatewayVhost{{Names: names, TLSMode: GatewayTLSACME}}}
		if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "real name") {
			t.Errorf("%q with ACME: got %v, want the real-name error", names, err)
		}
		g.Vhosts[0].TLSMode = GatewayTLSFiles
		if err := g.Validate(); err != nil {
			t.Errorf("%q with files: %v (a catch-all is fine with your own certificate)", names, err)
		}
	}
	g := GatewayConfig{ACMEEmail: "ops@example.test", Vhosts: []GatewayVhost{
		{Names: "shop.example www.shop.example", TLSMode: GatewayTLSACME},
		{ID: "b", Names: "blog.example", TLSMode: GatewayTLSFiles, CertPath: "/c", KeyPath: "/k"},
	}}
	if err := g.Validate(); err != nil {
		t.Fatalf("two vhosts with different sources must validate: %v", err)
	}
	g.Vhosts[1].Names = "blog.example WWW.shop.example"
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "already served") {
		t.Errorf("a name served twice must be refused, got %v", err)
	}
}

// The 0.1.37 single-vhost shape folds into one row on load, keeping the
// legacy stored pair (id "") and the paths; tls_mode none becomes the
// gateway-wide "TLS in front".
func TestGatewayNormalizeMigratesSingleVhost(t *testing.T) {
	g := GatewayConfig{ServerName: " shop.example  www.shop.example ", TLSMode: GatewayTLSUpload, ACMEEmail: "ops@x"}
	g.Normalize()
	if len(g.Vhosts) != 1 || g.Vhosts[0].Names != "shop.example www.shop.example" || g.Vhosts[0].ID != "" || g.Vhosts[0].ModeResolved() != GatewayTLSUpload {
		t.Errorf("migrated vhosts = %+v", g.Vhosts)
	}
	if g.ServerName != "" || g.TLSMode != "" {
		t.Error("legacy fields must be cleared once folded")
	}
	if g.Vhosts[0].CertPathResolved("/etc/unmask") != "/etc/unmask/gateway.crt" {
		t.Errorf("the migrated row must keep the legacy stored pair, got %s", g.Vhosts[0].CertPathResolved("/etc/unmask"))
	}
	n := GatewayConfig{ServerName: "_", TLSMode: GatewayTLSNone}
	n.Normalize()
	if !n.TLSInFront() || len(n.Vhosts) != 1 || !n.Vhosts[0].CatchAll() {
		t.Errorf("none migration = %+v", n)
	}
	if err := n.Validate(); err != nil {
		t.Errorf("TLS in front needs no certificate: %v", err)
	}
	if n.UsesACME() {
		t.Error("TLS in front never uses ACME")
	}
}

// The empty config is "no gateway"; a row with nothing but a name resolves
// to files with the image's default mount paths; a later row gets its own
// stored pair.
func TestGatewayDefaults(t *testing.T) {
	var g GatewayConfig
	if g.Active() {
		t.Error("an empty config must not be active")
	}
	if err := g.Validate(); err != nil {
		t.Errorf("an empty config must validate (it is the host-install state): %v", err)
	}
	v := GatewayVhost{Names: "_"}
	if v.ModeResolved() != GatewayTLSFiles || v.CertPathResolved("/etc/unmask") != GatewayDefaultCertPath || v.KeyPathResolved("/etc/unmask") != GatewayDefaultKeyPath {
		t.Errorf("empty mode/paths did not resolve to files at the default mount: %+v", v)
	}
	if g.ACMEDirectoryResolved() != ACMEDirectoryLetsEncrypt {
		t.Error("empty directory must resolve to Let's Encrypt production")
	}
	u := GatewayVhost{ID: "ab12", Names: "shop.example", TLSMode: GatewayTLSUpload}
	if u.CertPathResolved("/etc/unmask") != "/etc/unmask/gateway-ab12.crt" || u.KeyPathResolved("/etc/unmask") != "/etc/unmask/gateway-ab12.key" {
		t.Errorf("upload mode must resolve to the row's stored pair, got %s", u.CertPathResolved("/etc/unmask"))
	}
	if u.FirstName() != "shop.example" || (GatewayVhost{Names: "_"}).FirstName() != "" {
		t.Error("FirstName: the first real name, none for a catch-all")
	}
}
