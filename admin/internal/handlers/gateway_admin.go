package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The Gateway settings tab: the container gateway's hostname and where its
// certificate comes from.  See settings.GatewayConfig for what is
// deliberately not here.

// applyGatewayForm reads the gateway tab's form into g.  outDir is the
// render directory; a pasted certificate is stored under it so the nginx
// container reaches it through the shared volume.
func applyGatewayForm(g *settings.GatewayConfig, r *http.Request, outDir string) error {
	g.ServerName = strings.TrimSpace(r.FormValue("server_name"))
	if g.ServerName == "" {
		return errors.New("hostname: required (the name the gateway answers for)")
	}
	mode := strings.TrimSpace(r.FormValue("tls_mode"))
	switch mode {
	case settings.GatewayTLSACME, settings.GatewayTLSUpload, settings.GatewayTLSFiles:
	default:
		return fmt.Errorf("certificate source: unknown value %q", mode)
	}
	g.TLSMode = mode

	// Every field is kept regardless of the active mode, so switching modes
	// back and forth does not lose what was typed for the other one.
	g.ACMEEmail = strings.TrimSpace(r.FormValue("acme_email"))
	switch strings.TrimSpace(r.FormValue("acme_directory")) {
	case "", "production":
		g.ACMEDirectory = ""
		g.ACMEInsecure = false
	case "staging":
		g.ACMEDirectory = settings.ACMEDirectoryLetsEncryptStaging
		g.ACMEInsecure = false
	case "custom":
		g.ACMEDirectory = strings.TrimSpace(r.FormValue("acme_directory_custom"))
		// Skipping verification of the ACME server's certificate is only
		// meaningful against a private test server, so it rides the custom
		// choice alone: a public directory never gets it, however the box
		// was left.
		g.ACMEInsecure = r.FormValue("acme_insecure") == "1"
	default:
		return errors.New("ACME directory: unknown choice")
	}
	g.TLSCertPath = strings.TrimSpace(r.FormValue("tls_cert_path"))
	g.TLSKeyPath = strings.TrimSpace(r.FormValue("tls_key_path"))

	if mode == settings.GatewayTLSUpload {
		certPEM := strings.TrimSpace(r.FormValue("cert_pem"))
		chainPEM := strings.TrimSpace(r.FormValue("chain_pem"))
		keyPEM := strings.TrimSpace(r.FormValue("key_pem"))
		switch {
		case certPEM == "" && keyPEM == "":
			// Nothing pasted: keep the certificate already stored, which
			// must exist for the mode to mean anything.
			if _, err := os.Stat(settings.UploadedCertPath(outDir)); err != nil {
				return errors.New("certificate: paste the certificate and its private key (none is stored yet)")
			}
		case certPEM == "" || keyPEM == "":
			return errors.New("certificate: paste both the certificate and the private key")
		default:
			if err := storeUploadedCert(outDir, certPEM, chainPEM, keyPEM); err != nil {
				return err
			}
		}
	}
	return g.Validate()
}

// storeUploadedCert validates a pasted certificate + key pair and writes it
// under outDir/tls.  The chain (intermediates a commercial CA hands out
// separately) is appended to the certificate, which is how nginx wants it.
// The key file is 0600; the render directory is not world-readable either,
// but a private key gets its own lock regardless.
func storeUploadedCert(outDir, certPEM, chainPEM, keyPEM string) error {
	full := certPEM + "\n"
	if chainPEM != "" {
		full += chainPEM + "\n"
	}
	leaf, err := parseLeafCert(full)
	if err != nil {
		return err
	}
	if _, err := tls.X509KeyPair([]byte(full), []byte(keyPEM+"\n")); err != nil {
		return fmt.Errorf("certificate: the private key does not match the certificate, or is not a PEM key (%v)", err)
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("certificate: expired on %s", leaf.NotAfter.UTC().Format("2006-01-02"))
	}
	dir := filepath.Join(outDir, "tls")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("certificate: mkdir %s: %w", dir, err)
	}
	if err := writePrivate(settings.UploadedKeyPath(outDir), []byte(keyPEM+"\n"), 0o600); err != nil {
		return fmt.Errorf("certificate: store key: %w", err)
	}
	if err := writePrivate(settings.UploadedCertPath(outDir), []byte(full), 0o644); err != nil {
		return fmt.Errorf("certificate: store certificate: %w", err)
	}
	return nil
}

// writePrivate writes via a temp file in the same directory and renames it
// into place, so nginx never reads a half-written key.
func writePrivate(path string, b []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// parseLeafCert returns the first certificate in a PEM bundle.
func parseLeafCert(bundle string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(bundle))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate: not a PEM certificate (expected a -----BEGIN CERTIFICATE----- block)")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate: %v", err)
	}
	return c, nil
}

// gatewayCertView is what the tab shows about the certificate the gateway
// is serving right now -- read off its :443, so it reflects reality (an
// ACME issuance that has not happened yet shows as an error here).
type gatewayCertView struct {
	Checked   bool
	OK        bool
	Err       string
	Subject   string
	Issuer    string
	NotAfter  string
	DaysLeft  int
	NameMatch bool
	Names     string
}

// gatewayCertStatus dials the gateway and reports its served certificate.
// addr is host:port as the admin container reaches nginx (compose: nginx:443).
func gatewayCertStatus(addr, serverName string) gatewayCertView {
	v := gatewayCertView{Checked: true}
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // we want to SEE the certificate, whatever it is
	})
	if err != nil {
		v.Err = err.Error()
		return v
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		v.Err = "no certificate presented"
		return v
	}
	c := certs[0]
	v.OK = true
	v.Subject = dnLabel(c.Subject)
	v.Issuer = dnLabel(c.Issuer)
	v.NotAfter = c.NotAfter.UTC().Format("2006-01-02")
	v.DaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
	v.Names = strings.Join(c.DNSNames, ", ")
	if serverName != "" && serverName != "_" {
		v.NameMatch = c.VerifyHostname(serverName) == nil
	}
	return v
}

// gatewayAddr: where the admin reaches the gateway's :443.  The nginx
// service name under compose; overridable for other layouts.
func gatewayAddr() string {
	if a := strings.TrimSpace(os.Getenv("UNMASK_GATEWAY_ADDR")); a != "" {
		return a
	}
	return "nginx:443"
}

// uploadedCertInfo describes a stored (pasted) certificate without dialing
// anything, for the tab to show what is on disk.
func uploadedCertInfo(outDir string) (subject, issuer, notAfter string, ok bool) {
	b, err := os.ReadFile(settings.UploadedCertPath(outDir))
	if err != nil {
		return "", "", "", false
	}
	c, err := parseLeafCert(string(b))
	if err != nil {
		return "", "", "", false
	}
	return dnLabel(c.Subject), dnLabel(c.Issuer), c.NotAfter.UTC().Format("2006-01-02"), true
}

// nginxOutDir mirrors nginxconf.Render's default for the render directory.
func nginxOutDir(s settings.Settings) string {
	if s.Nginx.OutputDir != "" {
		return s.Nginx.OutputDir
	}
	return "/var/lib/unmask/nginx"
}

// dnLabel names a certificate party the way an operator reads it: the common
// name, with the organization when it adds something ("R11 (Let's Encrypt)",
// "Sectigo RSA Domain Validation Secure Server CA (Sectigo Limited)").  A
// name without a common name falls back to the organization alone.
func dnLabel(n pkix.Name) string {
	org := ""
	if len(n.Organization) > 0 {
		org = strings.TrimSpace(n.Organization[0])
	}
	cn := strings.TrimSpace(n.CommonName)
	switch {
	case cn == "":
		return org
	case org == "" || org == cn:
		return cn
	default:
		return cn + " (" + org + ")"
	}
}
