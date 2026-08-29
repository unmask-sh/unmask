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
	s.Gateway = settings.GatewayConfig{ServerName: "shop.example", TLSMode: settings.GatewayTLSFiles}
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

// A pasted certificate lands as the stored pair (key private), the config
// switches to upload mode, and a later save with the fields left blank keeps
// the stored pair -- the UI never echoes the key back, so "blank" must mean
// "unchanged", not "removed".
func TestGatewayUploadStoresPairAndKeepsItOnBlankSave(t *testing.T) {
	h, outDir := gatewayHandler(t)
	now := time.Now()
	certPEM, keyPEM := selfSignedPEM(t, "shop.example", now.Add(-time.Hour), now.Add(365*24*time.Hour))

	loc := postGateway(t, h, url.Values{
		"server_name": {"shop.example"},
		"tls_mode":    {settings.GatewayTLSUpload},
		"cert_pem":    {certPEM},
		"key_pem":     {keyPEM},
	})
	if !strings.Contains(loc, "saved=1") {
		t.Fatalf("upload save did not reach the success path: Location=%q", loc)
	}
	certPath := settings.UploadedCertPath(outDir)
	keyPath := settings.UploadedKeyPath(outDir)
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
	if saved.Gateway.TLSMode != settings.GatewayTLSUpload || saved.Gateway.ServerName != "shop.example" {
		t.Errorf("saved gateway = %+v, want upload mode for shop.example", saved.Gateway)
	}

	// Blank PEM fields on a later save: the pair stays.
	loc = postGateway(t, h, url.Values{
		"server_name": {"shop.example"},
		"tls_mode":    {settings.GatewayTLSUpload},
		"cert_pem":    {""},
		"key_pem":     {""},
	})
	if !strings.Contains(loc, "saved=1") {
		t.Fatalf("blank re-save must succeed while a pair is stored: Location=%q", loc)
	}
	if again, _ := os.ReadFile(certPath); string(again) != certPEM {
		t.Error("blank re-save replaced or removed the stored certificate")
	}

	// A pair that does not match is refused and the stored one is untouched.
	otherCert, _ := selfSignedPEM(t, "shop.example", now.Add(-time.Hour), now.Add(24*time.Hour))
	loc = postGateway(t, h, url.Values{
		"server_name": {"shop.example"},
		"tls_mode":    {settings.GatewayTLSUpload},
		"cert_pem":    {otherCert},
		"key_pem":     {keyPEM},
	})
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
	loc := postGateway(t, h, url.Values{
		"server_name": {"shop.example"},
		"tls_mode":    {settings.GatewayTLSUpload},
	})
	if strings.Contains(loc, "saved=1") {
		t.Fatal("upload mode with no certificate at all was accepted")
	}
	now := time.Now()
	certPEM, keyPEM := selfSignedPEM(t, "shop.example", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	loc = postGateway(t, h, url.Values{
		"server_name": {"shop.example"},
		"tls_mode":    {settings.GatewayTLSUpload},
		"cert_pem":    {certPEM},
		"key_pem":     {keyPEM},
	})
	if strings.Contains(loc, "saved=1") {
		t.Fatal("an expired certificate was accepted")
	}
	if _, err := os.Stat(settings.UploadedKeyPath(outDir)); err == nil {
		t.Error("a refused upload left its key on disk")
	}
	saved, _ := settings.Load(h.ConfigPath)
	if saved.Gateway.TLSMode != settings.GatewayTLSFiles {
		t.Errorf("a refused save changed the stored mode to %q", saved.Gateway.TLSMode)
	}
}

// The other two sources: ACME needs a contact and a real name; files need
// absolute paths.  The form maps the directory choice onto the URL.
func TestGatewayACMEAndFilesForm(t *testing.T) {
	h, _ := gatewayHandler(t)
	if loc := postGateway(t, h, url.Values{
		"server_name": {"shop.example"},
		"tls_mode":    {settings.GatewayTLSACME},
	}); strings.Contains(loc, "saved=1") {
		t.Fatal("ACME without a contact address was accepted")
	}
	if loc := postGateway(t, h, url.Values{
		"server_name":    {"shop.example"},
		"tls_mode":       {settings.GatewayTLSACME},
		"acme_email":     {"ops@shop.example"},
		"acme_directory": {"staging"},
	}); !strings.Contains(loc, "saved=1") {
		t.Fatalf("ACME staging save failed: Location=%q", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	if saved.Gateway.ACMEDirectory != settings.ACMEDirectoryLetsEncryptStaging || saved.Gateway.ACMEEmail != "ops@shop.example" {
		t.Errorf("saved ACME config = %+v", saved.Gateway)
	}
	if saved.Gateway.ACMEInsecure {
		t.Error("insecure must stay off unless a custom directory asks for it")
	}

	if loc := postGateway(t, h, url.Values{
		"server_name":   {"shop.example"},
		"tls_mode":      {settings.GatewayTLSFiles},
		"tls_cert_path": {"certs/fullchain.pem"},
		"tls_key_path":  {"/certs/privkey.pem"},
	}); strings.Contains(loc, "saved=1") {
		t.Fatal("a relative certificate path was accepted")
	}
	if loc := postGateway(t, h, url.Values{
		"server_name":   {"_"},
		"tls_mode":      {settings.GatewayTLSFiles},
		"tls_cert_path": {"/certs/fullchain.pem"},
		"tls_key_path":  {"/certs/privkey.pem"},
	}); !strings.Contains(loc, "saved=1") {
		t.Fatalf("files save failed: Location=%q", loc)
	}
	saved, _ = settings.Load(h.ConfigPath)
	if saved.Gateway.TLSMode != settings.GatewayTLSFiles || saved.Gateway.TLSCertPath != "/certs/fullchain.pem" {
		t.Errorf("saved files config = %+v", saved.Gateway)
	}
	if _, err := os.Stat(filepath.Join(h.cfg().Nginx.OutputDir, "gateway-tls.inc")); err != nil {
		t.Errorf("a gateway save must re-render the includes: %v", err)
	}
}

// The tab exists only for a gateway install: a host install (no gateway
// configured) must not grow a Gateway entry in the settings nav, while a
// gateway install renders the vhost and certificate cards.
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
	for _, want := range []string{`name="server_name"`, `name="tls_mode"`, `name="cert_pem"`, `name="key_pem"`, `name="acme_email"`, `name="tls_cert_path"`, `?section=gateway`} {
		if !strings.Contains(body, want) {
			t.Errorf("gateway tab lacks %s", want)
		}
	}
	if !strings.Contains(renderSettingsTab(t, h, "global"), "settings/gateway/") {
		t.Error("a gateway install does not show the Gateway tab in the settings nav")
	}
}
