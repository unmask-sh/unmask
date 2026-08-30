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
		"listen_http": {"1"}, "listen_https": {"1"},
		"hostnames_mode": {"custom"}, "hostnames_present": {"1"}, "hostnames": {hostnames},
		"certs_present": {"1"}, "acme_present": {"1"},
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

	// The SANs are the domains of a pasted certificate; a stale value in the
	// (hidden) field does not override them.
	loc = postGateway(t, h, oneCert("shop.example", "stale.example", settings.GatewayTLSUpload, nil))
	if !strings.Contains(loc, "saved=1") {
		t.Fatalf("stale domains: %s", loc)
	}
	saved, _ = settings.Load(h.ConfigPath)
	if saved.Gateway.Certificates[0].Domains != "shop.example www.shop.example" {
		t.Errorf("the SANs must be the domains of a pasted certificate: %+v", saved.Gateway.Certificates[0])
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
		"listen_http": {"1"}, "listen_https": {"1"},
		"hostnames_mode": {"custom"}, "hostnames_present": {"1"}, "hostnames": {"shop.example\nwww.shop.example\nblog.example"},
		"certs_present": {"1"}, "acme_present": {"1"},
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
	if strings.Contains(renderSettingsTab(t, h, "gateway"), `data-gw-uncovered`) {
		t.Error("every hostname is on a certificate, yet the tab warns")
	}

	// A hostname no certificate names: saved, and the tab warns.
	two.Set("hostnames", "shop.example www.shop.example blog.example extra.example")
	if loc := postGateway(t, h, two); !strings.Contains(loc, "saved=1") {
		t.Fatalf("a hostname without a certificate is a warning, not an error: %s", loc)
	}
	if body := renderSettingsTab(t, h, "gateway"); !strings.Contains(body, `data-gw-uncovered`) || !strings.Contains(body, "extra.example</code>") {
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

// A mounted certificate the admin can read brings its own domains, like a
// pasted one, and the tab shows them instead of the field; one it cannot
// read keeps whatever was typed.
func TestGatewayFilesReadsDomainsFromReadableCertificate(t *testing.T) {
	h, _ := gatewayHandler(t)
	now := time.Now()
	certPEM, _ := selfSignedPEM(t, "shop.example www.shop.example", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	dir := t.TempDir()
	certPath := filepath.Join(dir, "site.crt")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	f := oneCert("shop.example", "", settings.GatewayTLSFiles, url.Values{"cert_cert_path": {certPath}, "cert_key_path": {filepath.Join(dir, "site.key")}})
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("files save: %s", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	if saved.Gateway.Certificates[0].Domains != "shop.example www.shop.example" {
		t.Errorf("a readable certificate file must give the domains: %+v", saved.Gateway.Certificates[0])
	}
	body := renderSettingsTab(t, h, "gateway")
	if !strings.Contains(body, `data-gw-file-readable="1"`) || !strings.Contains(body, "shop.example www.shop.example</code>") {
		t.Error("the tab does not show the domains read from the file")
	}
	// A 0600 certificate: present, but the daemon may not read it -- the tab
	// says so (root reads anything, so only when not root).
	if os.Geteuid() != 0 {
		if err := os.Chmod(certPath, 0o000); err != nil {
			t.Fatal(err)
		}
		f = oneCert("shop.example", "typed.example", settings.GatewayTLSFiles, url.Values{"cert_cert_path": {certPath}, "cert_key_path": {filepath.Join(dir, "site.key")}})
		if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
			t.Fatalf("files save (denied): %s", loc)
		}
		if body := renderSettingsTab(t, h, "gateway"); !strings.Contains(body, "user unmask") || !strings.Contains(body, certPath+"</code>") {
			t.Error("the tab does not point at the unreadable certificate file")
		}
		_ = os.Chmod(certPath, 0o644)
	}
	// Unreadable (the nginx-only mount): the typed domains stand.
	f = oneCert("shop.example", "typed.example", settings.GatewayTLSFiles, url.Values{"cert_cert_path": {"/etc/unmask/tls/nowhere.pem"}, "cert_key_path": {"/etc/unmask/tls/nowhere.key"}})
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("files save (unreadable): %s", loc)
	}
	saved, _ = settings.Load(h.ConfigPath)
	if saved.Gateway.Certificates[0].Domains != "typed.example" {
		t.Errorf("an unreadable file must keep the typed domains: %+v", saved.Gateway.Certificates[0])
	}
	if strings.Contains(renderSettingsTab(t, h, "gateway"), `data-gw-file-readable="1"`) {
		t.Error("the tab claims to have read a file it cannot see")
	}
}

// A pasted certificate with a bare common name and no SAN (openssl's
// one-liner for localhost) still names its host; and a domain-less mounted
// file next to a custom list draws no warning -- it stands for every name.
func TestGatewayBareCommonNameAndDomainlessFile(t *testing.T) {
	h, _ := gatewayHandler(t)
	now := time.Now()
	certPEM, keyPEM := selfSignedPEM(t, "localhost", now.Add(-time.Hour), now.Add(24*time.Hour))
	certPEM = strings.TrimSpace(certPEM)
	loc := postGateway(t, h, oneCert("localhost", "", settings.GatewayTLSUpload, url.Values{"cert_cert_pem": {certPEM}, "cert_key_pem": {keyPEM}}))
	if !strings.Contains(loc, "saved=1") {
		t.Fatalf("upload: %s", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	if saved.Gateway.Certificates[0].Domains != "localhost" {
		t.Errorf("domains = %q, want localhost (from the SAN)", saved.Gateway.Certificates[0].Domains)
	}
	loc = postGateway(t, h, oneCert("shop.example www.shop.example", "", settings.GatewayTLSFiles, url.Values{"cert_cert_path": {"/etc/unmask/tls/nowhere.pem"}, "cert_key_path": {"/etc/unmask/tls/nowhere.key"}}))
	if !strings.Contains(loc, "saved=1") {
		t.Fatalf("files: %s", loc)
	}
	if strings.Contains(renderSettingsTab(t, h, "gateway"), `data-gw-uncovered`) {
		t.Error("a domain-less mounted certificate stands for every hostname; the tab must not warn")
	}
	vh, _ := os.ReadFile(filepath.Join(h.cfg().Nginx.OutputDir, "gateway-vhosts.inc"))
	if !strings.Contains(string(vh), "server_name shop.example www.shop.example;") {
		t.Errorf("the custom hostnames must be served the domain-less certificate:\n%s", vh)
	}
}

// The tab disables what does not apply instead of hiding it: the sections
// render as fieldsets with a presence marker, and the ACME account
// survives a save made while its card was disabled.
func TestGatewayDisabledSectionsKeepValues(t *testing.T) {
	h, _ := gatewayHandler(t)
	f := oneCert("shop.example", "shop.example", settings.GatewayTLSACME, url.Values{"acme_email": {"ops@shop.example"}, "acme_directory": {"staging"}})
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("acme save: %s", loc)
	}
	body := renderSettingsTab(t, h, "gateway")
	for _, want := range []string{`<fieldset data-gw-certs-card>`, `<fieldset data-gw-acme-card>`, `<fieldset class="field" data-gw-hosts-list>`, `name="certs_present"`, `name="acme_present"`, `name="hostnames_present"`} {
		if !strings.Contains(body, want) {
			t.Errorf("gateway tab lacks %s", want)
		}
	}
	// Switch the certificate to a mounted file: the ACME card is disabled
	// (not submitted) and the account must stay as it was.
	f = oneCert("shop.example", "", settings.GatewayTLSFiles, url.Values{"cert_cert_path": {"/c.pem"}, "cert_key_path": {"/k.pem"}})
	f.Del("acme_present")
	f.Del("acme_email")
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("files save: %s", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	if saved.Gateway.ACMEEmail != "ops@shop.example" || saved.Gateway.ACMEDirectory != settings.ACMEDirectoryLetsEncryptStaging {
		t.Errorf("a disabled ACME card must keep the account: %+v", saved.Gateway)
	}
	// "All hostnames" disables the list, which keeps its names.
	f.Set("hostnames_mode", "all")
	f.Del("hostnames_present")
	f.Del("hostnames")
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("all hostnames: %s", loc)
	}
	saved, _ = settings.Load(h.ConfigPath)
	if !saved.Gateway.HostnamesAll() || saved.Gateway.Hostnames.Names != "shop.example" {
		t.Errorf("the disabled custom list must keep its names: %+v", saved.Gateway.Hostnames)
	}
}

// The upstream saves from the tab; a bad upstream is refused; the tab
// offers the self-signed source, reports what the nginx container's
// environment carries, and shows settings > Network's trusted LB set as
// the proxies the visitor's address is taken from.
func TestGatewayUpstreamForm(t *testing.T) {
	// The GCP preset ticked under settings > Network, in the stored config
	// (a save reloads it from disk before rendering).
	s, err := settings.LoadFromYAML("")
	if err != nil {
		t.Fatal(err)
	}
	s.Nginx.OutputDir = t.TempDir()
	s.Nginx.TrustedLBPresets = []string{"gcp"}
	s.Gateway = settings.GatewayConfig{
		Hostnames:    settings.GatewayHostnames{Mode: settings.GatewayHostsCustom, Names: "shop.example"},
		Certificates: []settings.GatewayCertificate{{Mode: settings.GatewayTLSFiles, Domains: "shop.example"}},
	}
	h := modeHandler(t, s)
	status := filepath.Join(t.TempDir(), "gateway-nginx.status")
	if err := os.WriteFile(status, []byte("location_source=env\nupstream_env=http://app:80\ntrusted_proxies_env=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UNMASK_GATEWAY_STATUS", status)
	body := renderSettingsTab(t, h, "gateway")
	for _, want := range []string{`name="upstream"`, `value="selfsigned"`, "http://app:80</code>", "GCP HTTPS Load Balancer", `settings/network/`} {
		if !strings.Contains(body, want) {
			t.Errorf("gateway tab lacks %s", want)
		}
	}
	if strings.Contains(body, `name="trusted_proxies"`) {
		t.Error("the trusted proxies are settings > Network's; the tab must not carry a second list")
	}
	f := oneCert("shop.example", "", settings.GatewayTLSFiles, url.Values{"upstream": {"http://host.docker.internal:8080"}, "cert_cert_path": {"/c.pem"}, "cert_key_path": {"/k.pem"}})
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("upstream save: %s", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	if saved.Gateway.Upstream != "http://host.docker.internal:8080" {
		t.Errorf("saved upstream = %q", saved.Gateway.Upstream)
	}
	locInc, _ := os.ReadFile(filepath.Join(h.cfg().Nginx.OutputDir, "gateway-location.inc"))
	if !strings.Contains(string(locInc), "proxy_pass http://host.docker.internal:8080;") {
		t.Errorf("the save must render the proxy location:\n%s", locInc)
	}
	prx, _ := os.ReadFile(filepath.Join(h.cfg().Nginx.OutputDir, "gateway-proxies.inc"))
	if !strings.Contains(string(prx), "set_real_ip_from 130.211.0.0/22;") {
		t.Errorf("the gateway's real_ip ranges must come from the Network tab's trusted LBs:\n%s", prx)
	}
	f.Set("upstream", "host.docker.internal:8080")
	if loc := postGateway(t, h, f); strings.Contains(loc, "saved=1") {
		t.Fatal("an upstream without a scheme was accepted")
	}
	// Self-signed: nothing to type, the pair appears with the render.
	f = oneCert("shop.example", "", settings.GatewayTLSSelfSigned, url.Values{"upstream": {"http://app:3000"}})
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("self-signed save: %s", loc)
	}
	if _, err := os.Stat(settings.UploadedCertPath(h.cfg().Nginx.OutputDir, "")); err != nil {
		t.Errorf("the self-signed pair was not generated: %v", err)
	}
	if body := renderSettingsTab(t, h, "gateway"); !strings.Contains(body, `value="selfsigned" selected`) {
		t.Error("the tab does not show self-signed as selected")
	}
}

// http only (TLS terminated in front): the hostnames save with no
// certificate at all; https only drops the :80 server and refuses Let's
// Encrypt; neither is refused.
func TestGatewayListenForm(t *testing.T) {
	h, _ := gatewayHandler(t)
	f := url.Values{"listen_http": {"1"}, "hostnames_mode": {"all"}}
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("http only: %s", loc)
	}
	saved, _ := settings.Load(h.ConfigPath)
	if !saved.Gateway.TLSInFront() || saved.Gateway.ListenHTTPS() || !saved.Gateway.ListenHTTP() || !saved.Gateway.HostnamesAll() {
		t.Errorf("saved %+v", saved.Gateway)
	}
	// The certificates section was disabled (not submitted): the stored
	// certificate and the custom list survive for when https comes back.
	if len(saved.Gateway.Certificates) != 1 || saved.Gateway.Certificates[0].Domains != "shop.example" || saved.Gateway.Hostnames.Names != "shop.example" {
		t.Errorf("disabled sections must keep their stored values: %+v", saved.Gateway)
	}
	body := renderSettingsTab(t, h, "gateway")
	if !strings.Contains(body, `name="listen_http" value="1" data-gw-listen checked`) || !strings.Contains(body, `name="listen_https" value="1" data-gw-listen>`) {
		t.Error("the tab does not show http ticked and https unticked")
	}
	if !strings.Contains(body, `name="hostnames_mode" value="all" data-gw-hosts checked`) {
		t.Error("the tab does not show all hostnames as selected")
	}
	// Both again with every certificate removed: a certificate is required.
	if loc := postGateway(t, h, url.Values{"listen_http": {"1"}, "listen_https": {"1"}, "hostnames_mode": {"all"}, "certs_present": {"1"}}); strings.Contains(loc, "saved=1") {
		t.Fatal("https with no certificate was accepted")
	}
	// Both again with the section untouched (no marker): the stored one serves.
	if loc := postGateway(t, h, url.Values{"listen_http": {"1"}, "listen_https": {"1"}, "hostnames_mode": {"all"}}); !strings.Contains(loc, "saved=1") {
		t.Fatalf("https back with the stored certificate: %s", loc)
	}
	// Neither.
	if loc := postGateway(t, h, url.Values{"hostnames_mode": {"all"}}); strings.Contains(loc, "saved=1") {
		t.Fatal("a gateway listening on nothing was accepted")
	}
	// https only with a mounted certificate: saved, the :80 server dropped.
	f = oneCert("shop.example", "", settings.GatewayTLSFiles, url.Values{"listen_https": {"1"}, "cert_cert_path": {"/c.pem"}, "cert_key_path": {"/k.pem"}})
	f.Del("listen_http")
	if loc := postGateway(t, h, f); !strings.Contains(loc, "saved=1") {
		t.Fatalf("https only: %s", loc)
	}
	vh, _ := os.ReadFile(filepath.Join(h.cfg().Nginx.OutputDir, "gateway-vhosts.inc"))
	if !strings.Contains(string(vh), "# unmask-gateway-http: none") || !strings.Contains(string(vh), "server_name shop.example;") {
		t.Errorf("https only must mark the missing :80 and keep the :443 blocks:\n%s", vh)
	}
	// https only + Let's Encrypt: no :80 for http-01.
	f = oneCert("shop.example", "shop.example", settings.GatewayTLSACME, url.Values{"listen_https": {"1"}, "acme_email": {"ops@shop.example"}})
	f.Del("listen_http")
	if loc := postGateway(t, h, f); strings.Contains(loc, "saved=1") {
		t.Fatal("Let's Encrypt without :80 was accepted")
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
	for _, want := range []string{`name="hostnames_mode"`, `name="hostnames"`, `name="cert_domains"`, `data-gw-domains-auto`, `name="cert_mode"`, `name="cert_cert_pem"`, `name="cert_key_pem"`, `name="acme_email"`, `name="cert_cert_path"`, `data-gw-cert-add`, `data-gw-cert-template`, `?section=gateway`, `name="hostnames_mode" value="custom" data-gw-hosts checked`, ">shop.example</textarea>"} {
		if !strings.Contains(body, want) {
			t.Errorf("gateway tab lacks %s", want)
		}
	}
	if n := strings.Count(body, `data-gw-cert data-gw-file-readable=`); n != 2 { // one entry + the template
		t.Errorf("expected one rendered entry plus the template, got %d", n)
	}
	if !strings.Contains(renderSettingsTab(t, h, "global"), "settings/gateway/") {
		t.Error("a gateway install does not show the Gateway tab in the settings nav")
	}
}
