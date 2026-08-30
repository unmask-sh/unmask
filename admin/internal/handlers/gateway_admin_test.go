package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// selfSignedPEM returns a certificate/key pair for the names, valid over
// the given window.  What a buyer pastes into the Gateway tab, minus the CA.
func selfSignedPEM(t *testing.T, names string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sans := strings.Fields(names)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: sans[0]},
		DNSNames:     sans,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
}

func gatewayHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	s, err := settings.LoadFromYAML("")
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	s.Nginx.OutputDir = outDir
	s.Gateway = settings.GatewayConfig{
		Hostnames:    settings.GatewayHostnames{Mode: settings.GatewayHostsCustom, Names: "shop.example"},
		Certificates: []settings.GatewayCertificate{{Mode: settings.GatewayTLSFiles, Domains: "shop.example"}},
	}
	h := modeHandler(t, s)
	return h, outDir
}

func postGateway(t *testing.T, h *Handler, form url.Values) string {
	t.Helper()
	form.Set("section", "gateway")
	r := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=gateway",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, r)
	return rr.Header().Get("Location")
}

// oneCert: a custom hostname list plus a single certificate entry.
func oneCert(hostnames, domains, mode string, extra url.Values) url.Values {
	f := url.Values{
		"hostnames_mode": {"custom"}, "hostnames": {hostnames},
		"cert_id": {""}, "cert_domains": {domains}, "cert_mode": {mode},
		"cert_cert_path": {""}, "cert_key_path": {""},
		"cert_cert_pem": {""}, "cert_chain_pem": {""}, "cert_key_pem": {""},
	}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

// A pasted certificate lands as the entry's stored pair (key private), its
// SANs become the entry's domains, and a later save with the fields left
// blank keeps the stored pair -- the UI never echoes the key back, so
// "blank" must mean "unchanged", not "removed".
func TestGatewayUploadStoresPairAndKeepsItOnBlankSave(t *testing.T) {
	h, outDir := gatewayHandler(t)
	now := time.Now()
	certPEM, keyPEM := selfSignedPEM(t, "shop.example www.shop.example", now.Add(-time.Hour), now.Add(365*24*time.Hour))

	loc := postGateway(t, h, oneCert("shop.example", "", settings.GatewayTLSUpload, url.Values{"cert_cert_pem": {certPEM}, "cert_key_pem": {keyPEM}}))
	if !strings.Contains(loc, "saved=1") {
		t.Fatalf("upload save did not reach the success path: Location=%q", loc)
	}
	certPath := settings.UploadedCertPath(outDir, "")
	keyPath := settings.UploadedKeyPath(outDir, "")
	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("stored certificate: %v", err)
	}
	if string(gotCert) != certPEM {
		t.Error("stored certificate differs from the pasted one")
	}
	ki, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stored key: %v", err)
	}
	if ki.Mode().Perm() != 0o600 {
		t.Errorf("stored key mode = %o, want 600 (nginx reads it as root; nobody else may)", ki.Mode().Perm())
	}
	if ci, _ := os.Stat(certPath); ci.Mode().Perm()&0o044 == 0 {
		t.Errorf("stored certificate mode = %o; nginx workers must be able to read it", ci.Mode().Perm())
	}
	saved, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	g := saved.Gateway
	if len(g.Certificates) != 1 || g.Certificates[0].ModeResolved() != settings.GatewayTLSUpload || g.Certificates[0].Domains != "shop.example www.shop.example" {
		t.Errorf("saved gateway = %+v, want one upload certificate with the domains read off its SANs", g)
	}
	if g.HostnamesAll() || g.Hostnames.Names != "shop.example" {
		t.Errorf("saved hostnames = %+v", g.Hostnames)
	}
	if g.ServerName != "" || g.Vhosts != nil {
		t.Error("a save must write hostnames + certificates, not the earlier shapes")
	}

	// Blank PEM fields on a later save: the pair stays, and so do the domains.
	loc = postGateway(t, h, oneCert("shop.example", "", settings.GatewayTLSUpload, nil))
	if !strings.Contains(loc, "saved=1") {
		t.Fatalf("blank re-save must succeed while a pair is stored: Location=%q", loc)
	}
	if again, _ := os.ReadFile(certPath); string(again) != certPEM {
		t.Error("blank re-save replaced or removed the stored certificate")
	}
	saved, _ = settings.Load(h.ConfigPath)
	if saved.Gateway.Certificates[0].Domains != "shop.example www.shop.example" {
		t.Errorf("blank re-save lost the domains: %+v", saved.Gateway.Certificates[0])
	}

	// Typed domains win over the SANs.
	loc = postGateway(t, h, oneCert("shop.example", "shop.example", settings.GatewayTLSUpload, nil))
	if !strings.Contains(loc, "saved=1") {
		t.Fatalf("typed domains: %s", loc)
	}
	saved, _ = settings.Load(h.ConfigPath)
	if saved.Gateway.Certificates[0].Domains != "shop.example" {
		t.Errorf("typed domains must override the SANs: %+v", saved.Gateway.Certificates[0])
	}

	// A pair that does not match is refused and the stored one is untouched.
	otherCert, _ := selfSignedPEM(t, "shop.example", now.Add(-time.Hour), now.Add(24*time.Hour))
	loc = postGateway(t, h, oneCert("shop.example", "", settings.GatewayTLSUpload, url.Values{"cert_cert_pem": {otherCert}, "cert_key_pem": {keyPEM}}))
	if strings.Contains(loc, "saved=1") {
		t.Fatal("a certificate that does not match the key was accepted")
	}
	if again, _ := os.ReadFile(certPath); string(again) != certPEM {
		t.Error("a refused upload overwrote the stored certificate")
	}
}

// Upload mode with nothing stored and nothing pasted has no certificate to
// serve; expired material is refused up front rather than at the next reload.
func TestGatewayUploadRefusesMissingAndExpired(t *testing.T) {
	h, outDir := gatewayHandler(t)
	loc := postGateway(t, h, oneCert("shop.example", "", settings.GatewayTLSUpload, nil))
	if strings.Contains(loc, "saved=1") {
		t.Fatal("upload mode with no certificate at all was accepted")
	}
	now := time.Now()
	certPEM, keyPEM := selfSignedPEM(t, "shop.example", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	loc = postGateway(t, h, oneCert("shop.example", "", settings.GatewayTLSUpload, url.Values{"cert_cert_pem": {certPEM}, "cert_key_pem": {keyPEM}}))
	if strings.Contains(loc, "saved=1") {
		t.Fatal("an expired certificate was accepted")
	}
	if _, err := os.Stat(settings.UploadedKeyPath(outDir, "")); err == nil {
		t.Error("a refused upload left its key on disk")
	}
	saved, _ := settings.Load(h.ConfigPath)
	if saved.Gateway.Certificates[0].ModeResolved() != settings.GatewayTLSFiles {
		t.Errorf("a refused save changed the stored mode to %q", saved.Gateway.Certificates[0].ModeResolved())
	}
}

// Three hostnames, two certificates: Let's Encrypt (staging) for the shop
// names, a mounted pair for the blog.  A hostname no certificate names is
// saved with a warning; a domain on two certificates is refused; a relative
// path is refused; the second entry gets an id of its own.
func TestGatewayTwoCertificatesForm(t *testing.T) {
	h, _ := gatewayHandler(t)
	two := url.Values{
		"hostnames_mode": {"custom"}, "hostnames": {"shop.example\nwww.shop.example\nblog.example"},
		"cert_id":        {"", ""},
		"cert_domains":   {"shop.example www.shop.example", "blog.example"},
		"cert_mode":      {settings.GatewayTLSACME, settings.GatewayTLSFiles},
		"cert_cert_path": {"", "/certs/default.pem"}, "cert_key_path": {"", "/certs/default.key"},
		"cert_cert_pem": {"", ""}, "cert_chain_pem": {"", ""}, "cert_key_pem": {"", ""},
	}
	if loc := postGateway(t, h, two); strings.Contains(loc, "saved=1") {
		t.Fatal("ACME without a contact address was accepted")
	}
	two.Set("acme_email", "ops@shop.example")
	two.Set("acme_directory", "staging")
	if loc := postGateway(t, h, two); !strings.Contains(loc, "saved=1") {
		t.Fatalf("two-certificate save failed: Location=%q", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	g := saved.Gateway
	if g.Hostnames.Names != "shop.example www.shop.example blog.example" || g.HostnamesAll() {
		t.Errorf("hostnames = %+v", g.Hostnames)
	}
	if len(g.Certificates) != 2 || g.Certificates[0].Domains != "shop.example www.shop.example" || g.Certificates[0].ModeResolved() != settings.GatewayTLSACME {
		t.Errorf("first certificate = %+v", g.Certificates)
	}
	if g.Certificates[1].Domains != "blog.example" || g.Certificates[1].CertPath != "/certs/default.pem" || g.Certificates[1].ID == "" {
		t.Errorf("second certificate = %+v (wants the blog pair with its own id)", g.Certificates[1])
	}
	if g.ACMEDirectory != settings.ACMEDirectoryLetsEncryptStaging || g.ACMEInsecure {
		t.Errorf("ACME account = %+v", g)
	}
	if _, err := os.Stat(filepath.Join(h.cfg().Nginx.OutputDir, "gateway-vhosts.inc")); err != nil {
		t.Errorf("a gateway save must re-render the includes: %v", err)
	}
	if strings.Contains(renderSettingsTab(t, h, "gateway"), `class="gw-warn"`) {
		t.Error("every hostname is on a certificate, yet the tab warns")
	}

	// A hostname no certificate names: saved, and the tab warns.
	two.Set("hostnames", "shop.example www.shop.example blog.example extra.example")
	if loc := postGateway(t, h, two); !strings.Contains(loc, "saved=1") {
		t.Fatalf("a hostname without a certificate is a warning, not an error: %s", loc)
	}
	if body := renderSettingsTab(t, h, "gateway"); !strings.Contains(body, `class="gw-warn"`) || !strings.Contains(body, "extra.example</code>") {
		t.Error("the tab does not warn about the uncovered hostname")
	}
	// A domain on two certificates.
	two["cert_domains"] = []string{"shop.example www.shop.example", "www.shop.example blog.example"}
	if loc := postGateway(t, h, two); strings.Contains(loc, "saved=1") {
		t.Fatal("a domain on two certificates was accepted")
	}
	two["cert_domains"] = []string{"shop.example www.shop.example", "blog.example"}
	two["cert_cert_path"] = []string{"", "certs/relative.pem"}
	if loc := postGateway(t, h, two); strings.Contains(loc, "saved=1") {
		t.Fatal("a relative certificate path was accepted")
	}
}

// TLS terminated in front: the hostnames save with no certificate at all.
func TestGatewayTLSInFrontForm(t *testing.T) {
	h, _ := gatewayHandler(t)
	f := url.Values{"tls": {"none"}, "hostnames_mode": {"all"}}
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("none: %s", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	if !saved.Gateway.TLSInFront() || !saved.Gateway.HostnamesAll() || len(saved.Gateway.Certificates) != 0 {
		t.Errorf("saved %+v", saved.Gateway)
	}
	body := renderSettingsTab(t, h, "gateway")
	if !strings.Contains(body, `name="tls" value="none" data-gw-tls checked`) {
		t.Error("the tab does not show TLS in front as selected")
	}
	if !strings.Contains(body, `name="hostnames_mode" value="all" data-gw-hosts checked`) {
		t.Error("the tab does not show all hostnames as selected")
	}
	// Back to TLS here: a certificate is required again.
	if loc := postGateway(t, h, url.Values{"tls": {"here"}, "hostnames_mode": {"all"}}); strings.Contains(loc, "saved=1") {
		t.Fatal("TLS here with no certificate was accepted")
	}
}

// The tab exists only for a gateway install: a host install (no gateway
// configured) must not grow a Gateway entry in the settings nav, while a
// gateway install renders the hostnames card and one certificate entry per
// certificate with the add/remove controls.
func TestGatewayTabRendersOnlyForGatewayInstalls(t *testing.T) {
	s, err := settings.LoadFromYAML("")
	if err != nil {
		t.Fatal(err)
	}
	s.Nginx.OutputDir = t.TempDir()
	host := modeHandler(t, s)
	if body := renderSettingsTab(t, host, "global"); strings.Contains(body, "settings/gateway/") {
		t.Error("a host install shows a Gateway tab in the settings nav")
	}

	h, _ := gatewayHandler(t)
	body := renderSettingsTab(t, h, "gateway")
	for _, want := range []string{`name="hostnames_mode"`, `name="hostnames"`, `name="cert_domains"`, `name="cert_mode"`, `name="cert_cert_pem"`, `name="cert_key_pem"`, `name="acme_email"`, `name="cert_cert_path"`, `data-gw-cert-add`, `data-gw-cert-template`, `?section=gateway`, `name="hostnames_mode" value="custom" data-gw-hosts checked`, ">shop.example</textarea>"} {
		if !strings.Contains(body, want) {
			t.Errorf("gateway tab lacks %s", want)
		}
	}
	if strings.Count(body, `data-gw-cert>`) != 2 { // one entry + the template
		t.Errorf("expected one rendered entry plus the template, got %d", strings.Count(body, `data-gw-cert>`))
	}
	if !strings.Contains(renderSettingsTab(t, h, "global"), "settings/gateway/") {
		t.Error("a gateway install does not show the Gateway tab in the settings nav")
	}
}
