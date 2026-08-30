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

// selfSignedPEM returns a certificate/key pair for name, valid over the
// given window.  What a buyer pastes into the Gateway tab, minus the CA.
func selfSignedPEM(t *testing.T, name string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
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
	s.Gateway = settings.GatewayConfig{Vhosts: []settings.GatewayVhost{{Names: "shop.example", TLSMode: settings.GatewayTLSFiles}}}
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

// oneVhost builds the row arrays for a single vhost.
func oneVhost(kind, names, mode string, extra url.Values) url.Values {
	f := url.Values{"vh_id": {""}, "vh_kind": {kind}, "vh_names": {names}, "vh_mode": {mode}, "vh_cert_path": {""}, "vh_key_path": {""}, "vh_cert_pem": {""}, "vh_chain_pem": {""}, "vh_key_pem": {""}}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

// A pasted certificate lands as the row's stored pair (key private), the
// row switches to upload mode, and a later save with the fields left blank
// keeps the stored pair -- the UI never echoes the key back, so "blank"
// must mean "unchanged", not "removed".
func TestGatewayUploadStoresPairAndKeepsItOnBlankSave(t *testing.T) {
	h, outDir := gatewayHandler(t)
	now := time.Now()
	certPEM, keyPEM := selfSignedPEM(t, "shop.example", now.Add(-time.Hour), now.Add(365*24*time.Hour))

	loc := postGateway(t, h, oneVhost("named", "shop.example", settings.GatewayTLSUpload, url.Values{"vh_cert_pem": {certPEM}, "vh_key_pem": {keyPEM}}))
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
	if len(saved.Gateway.Vhosts) != 1 || saved.Gateway.Vhosts[0].ModeResolved() != settings.GatewayTLSUpload || saved.Gateway.Vhosts[0].Names != "shop.example" {
		t.Errorf("saved gateway = %+v, want one upload vhost for shop.example", saved.Gateway)
	}
	if saved.Gateway.ServerName != "" {
		t.Error("a save must write the vhost list, not the 0.1.37 fields")
	}

	// Blank PEM fields on a later save: the pair stays.
	loc = postGateway(t, h, oneVhost("named", "shop.example", settings.GatewayTLSUpload, nil))
	if !strings.Contains(loc, "saved=1") {
		t.Fatalf("blank re-save must succeed while a pair is stored: Location=%q", loc)
	}
	if again, _ := os.ReadFile(certPath); string(again) != certPEM {
		t.Error("blank re-save replaced or removed the stored certificate")
	}

	// A pair that does not match is refused and the stored one is untouched.
	otherCert, _ := selfSignedPEM(t, "shop.example", now.Add(-time.Hour), now.Add(24*time.Hour))
	loc = postGateway(t, h, oneVhost("named", "shop.example", settings.GatewayTLSUpload, url.Values{"vh_cert_pem": {otherCert}, "vh_key_pem": {keyPEM}}))
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
	loc := postGateway(t, h, oneVhost("named", "shop.example", settings.GatewayTLSUpload, nil))
	if strings.Contains(loc, "saved=1") {
		t.Fatal("upload mode with no certificate at all was accepted")
	}
	now := time.Now()
	certPEM, keyPEM := selfSignedPEM(t, "shop.example", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	loc = postGateway(t, h, oneVhost("named", "shop.example", settings.GatewayTLSUpload, url.Values{"vh_cert_pem": {certPEM}, "vh_key_pem": {keyPEM}}))
	if strings.Contains(loc, "saved=1") {
		t.Fatal("an expired certificate was accepted")
	}
	if _, err := os.Stat(settings.UploadedKeyPath(outDir, "")); err == nil {
		t.Error("a refused upload left its key on disk")
	}
	saved, _ := settings.Load(h.ConfigPath)
	if saved.Gateway.Vhosts[0].ModeResolved() != settings.GatewayTLSFiles {
		t.Errorf("a refused save changed the stored mode to %q", saved.Gateway.Vhosts[0].ModeResolved())
	}
}

// Two rows: the named one on Let's Encrypt (staging), the catch-all on files.
// The second row gets an id of its own for a stored pair; ACME needs the
// account; a relative path is refused.
func TestGatewayTwoVhostsForm(t *testing.T) {
	h, _ := gatewayHandler(t)
	two := url.Values{
		"vh_id": {"", ""}, "vh_kind": {"named", "any"}, "vh_names": {"shop.example www.shop.example", ""},
		"vh_mode":      {settings.GatewayTLSACME, settings.GatewayTLSFiles},
		"vh_cert_path": {"", "/certs/default.pem"}, "vh_key_path": {"", "/certs/default.key"},
		"vh_cert_pem": {"", ""}, "vh_chain_pem": {"", ""}, "vh_key_pem": {"", ""},
	}
	if loc := postGateway(t, h, two); strings.Contains(loc, "saved=1") {
		t.Fatal("ACME without a contact address was accepted")
	}
	two.Set("acme_email", "ops@shop.example")
	two.Set("acme_directory", "staging")
	if loc := postGateway(t, h, two); !strings.Contains(loc, "saved=1") {
		t.Fatalf("two-vhost save failed: Location=%q", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	g := saved.Gateway
	if len(g.Vhosts) != 2 || g.Vhosts[0].Names != "shop.example www.shop.example" || g.Vhosts[0].ModeResolved() != settings.GatewayTLSACME {
		t.Errorf("first vhost = %+v", g.Vhosts)
	}
	if !g.Vhosts[1].CatchAll() || g.Vhosts[1].CertPath != "/certs/default.pem" || g.Vhosts[1].ID == "" {
		t.Errorf("second vhost = %+v (wants a catch-all with its own id)", g.Vhosts[1])
	}
	if g.ACMEDirectory != settings.ACMEDirectoryLetsEncryptStaging || g.ACMEInsecure {
		t.Errorf("ACME account = %+v", g)
	}
	if _, err := os.Stat(filepath.Join(h.cfg().Nginx.OutputDir, "gateway-vhosts.inc")); err != nil {
		t.Errorf("a gateway save must re-render the includes: %v", err)
	}
	two.Set("vh_cert_path", "certs/relative.pem")
	two["vh_cert_path"] = []string{"", "certs/relative.pem"}
	if loc := postGateway(t, h, two); strings.Contains(loc, "saved=1") {
		t.Fatal("a relative certificate path was accepted")
	}
}

// TLS terminated in front: the vhosts save with no certificate at all.
func TestGatewayTLSInFrontForm(t *testing.T) {
	h, _ := gatewayHandler(t)
	f := oneVhost("any", "", settings.GatewayTLSFiles, nil)
	f.Set("tls", "none")
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("none: %s", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	if !saved.Gateway.TLSInFront() || !saved.Gateway.Vhosts[0].CatchAll() {
		t.Errorf("saved %+v", saved.Gateway)
	}
	body := renderSettingsTab(t, h, "gateway")
	if !strings.Contains(body, `name="tls" value="none" data-gw-tls checked`) {
		t.Error("the tab does not show TLS in front as selected")
	}
}

// The tab exists only for a gateway install: a host install (no gateway
// configured) must not grow a Gateway entry in the settings nav, while a
// gateway install renders one row per vhost with the add/remove controls.
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
	for _, want := range []string{`name="vh_names"`, `name="vh_mode"`, `name="vh_cert_pem"`, `name="vh_key_pem"`, `name="acme_email"`, `name="vh_cert_path"`, `data-gw-vhost-add`, `data-gw-vhost-template`, `?section=gateway`} {
		if !strings.Contains(body, want) {
			t.Errorf("gateway tab lacks %s", want)
		}
	}
	if strings.Count(body, `data-gw-vhost `) != 2 { // one row + the template
		t.Errorf("expected one rendered row plus the template, got %d", strings.Count(body, `data-gw-vhost `))
	}
	if !strings.Contains(renderSettingsTab(t, h, "global"), "settings/gateway/") {
		t.Error("a gateway install does not show the Gateway tab in the settings nav")
	}
}
