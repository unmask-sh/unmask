package settings

import (
	"strings"
	"testing"
)

// Every gateway value lands inside a rendered nginx directive, so the
// validation is first of all about what a value must not carry: anything
// that could end the directive and start another.
func TestGatewayValidateRejectsDirectiveBreakers(t *testing.T) {
	base := GatewayConfig{ServerName: "example.test", TLSMode: GatewayTLSACME, ACMEEmail: "ops@example.test"}
	if err := base.Validate(); err != nil {
		t.Fatalf("a plain ACME config must validate: %v", err)
	}
	bad := []GatewayConfig{
		{ServerName: "example.test; return 200", TLSMode: GatewayTLSFiles},
		{ServerName: "example.test\ninclude /etc/passwd", TLSMode: GatewayTLSFiles},
		{ServerName: "example.test", TLSMode: GatewayTLSACME, ACMEEmail: "a@b; }"},
		{ServerName: "example.test", TLSMode: GatewayTLSACME, ACMEEmail: "ops@example.test", ACMEDirectory: "http://plain.example/dir"},
		{ServerName: "example.test", TLSMode: GatewayTLSFiles, TLSCertPath: "relative/cert.pem", TLSKeyPath: "/k"},
		{ServerName: "example.test", TLSMode: GatewayTLSFiles, TLSCertPath: "/c.pem", TLSKeyPath: "/k.pem # x"},
	}
	for i, g := range bad {
		if err := g.Validate(); err == nil {
			t.Errorf("case %d: %+v validated; it must not", i, g)
		}
	}
}

// ACME issues for names: a catch-all or a wildcard cannot be its subject.
func TestGatewayValidateACMENeedsARealName(t *testing.T) {
	for _, name := range []string{"_", "*.example.test"} {
		g := GatewayConfig{ServerName: name, TLSMode: GatewayTLSACME, ACMEEmail: "ops@example.test"}
		if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "real name") {
			t.Errorf("%q with ACME: got %v, want the real-name error", name, err)
		}
		g.TLSMode = GatewayTLSFiles
		if err := g.Validate(); err != nil {
			t.Errorf("%q with files: %v (a catch-all is fine with your own certificate)", name, err)
		}
	}
}

// The empty config is "no gateway", and resolves to files with the image's
// default mount paths when it is later switched on with nothing else set.
func TestGatewayDefaults(t *testing.T) {
	var g GatewayConfig
	if g.Active() {
		t.Error("an empty config must not be active")
	}
	if err := g.Validate(); err != nil {
		t.Errorf("an empty config must validate (it is the host-install state): %v", err)
	}
	g.ServerName = "_"
	if g.TLSModeResolved() != GatewayTLSFiles || g.CertPathResolved("/etc/unmask") != GatewayDefaultCertPath || g.KeyPathResolved("/etc/unmask") != GatewayDefaultKeyPath {
		t.Errorf("empty mode/paths did not resolve to files at the default mount: %+v", g)
	}
	if g.ACMEDirectoryResolved() != ACMEDirectoryLetsEncrypt {
		t.Error("empty directory must resolve to Let's Encrypt production")
	}
	g.TLSMode = GatewayTLSUpload
	if g.CertPathResolved("/etc/unmask") != "/etc/unmask/gateway.crt" {
		t.Errorf("upload mode must resolve to the stored pair under the render dir, got %s", g.CertPathResolved("/etc/unmask"))
	}
}
