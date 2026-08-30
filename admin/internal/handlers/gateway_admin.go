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

// applyGatewayForm reads settings > Gateway: where TLS ends, which
// hostnames the gateway answers for (all, or a list), the certificates
// (parallel arrays, one entry each in DOM order, a <select> per entry and
// never a checkbox), and the ACME account.  A pasted pair is checked and
// stored under the entry's id before the config is validated, and its
// SANs are the entry's domains (the field is typed for Let's Encrypt and,
// optionally, for files).
func applyGatewayForm(g *settings.GatewayConfig, r *http.Request, outDir string) error {
	g.Normalize()
	if err := r.ParseForm(); err != nil {
		return err
	}
	switch strings.TrimSpace(r.FormValue("tls")) {
	case "", "here":
		g.TLS = ""
	case settings.GatewayTLSNone:
		g.TLS = settings.GatewayTLSNone
	default:
		return errors.New("TLS: unknown choice")
	}
	switch strings.TrimSpace(r.FormValue("hostnames_mode")) {
	case "", settings.GatewayHostsAll:
		g.Hostnames = settings.GatewayHostnames{Mode: settings.GatewayHostsAll}
	case settings.GatewayHostsCustom:
		g.Hostnames = settings.GatewayHostnames{Mode: settings.GatewayHostsCustom, Names: strings.Join(strings.Fields(strings.ToLower(r.FormValue("hostnames"))), " ")}
	default:
		return errors.New("hostnames: unknown choice")
	}
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
		g.ACMEInsecure = r.FormValue("acme_insecure") == "1"
	default:
		return errors.New("ACME directory: unknown choice")
	}

	col := func(k string) []string { return r.Form[k] }
	ids, modes, domains := col("cert_id"), col("cert_mode"), col("cert_domains")
	certPaths, keyPaths := col("cert_cert_path"), col("cert_key_path")
	certPEMs, chainPEMs, keyPEMs := col("cert_cert_pem"), col("cert_chain_pem"), col("cert_key_pem")
	at := func(a []string, i int) string {
		if i < len(a) {
			return strings.TrimSpace(a[i])
		}
		return ""
	}
	var certs []settings.GatewayCertificate
	for i := 0; i < len(modes); i++ {
		c := settings.GatewayCertificate{ID: at(ids, i)}
		if c.ID == "" && i > 0 {
			c.ID = settings.NewCertificateID()
		}
		mode := at(modes, i)
		switch mode {
		case settings.GatewayTLSACME, settings.GatewayTLSUpload, settings.GatewayTLSFiles:
		case "":
			mode = settings.GatewayTLSFiles
		default:
			return fmt.Errorf("certificate %d: unknown source %q", i+1, mode)
		}
		c.Mode = mode
		c.Domains = strings.Join(strings.Fields(strings.ToLower(at(domains, i))), " ")
		c.CertPath = at(certPaths, i)
		c.KeyPath = at(keyPaths, i)
		if mode == settings.GatewayTLSUpload && !g.TLSInFront() {
			certPEM, chainPEM, keyPEM := at(certPEMs, i), at(chainPEMs, i), at(keyPEMs, i)
			switch {
			case certPEM == "" && keyPEM == "":
				b, err := os.ReadFile(settings.UploadedCertPath(outDir, c.ID))
				if err != nil {
					return fmt.Errorf("certificate %d: paste the certificate and its private key (none is stored yet)", i+1)
				}
				if leaf, err := parseLeafCert(string(b)); err == nil {
					c.Domains = strings.Join(certDomains(leaf), " ")
				}
			case certPEM == "" || keyPEM == "":
				return fmt.Errorf("certificate %d: paste both the certificate and the private key", i+1)
			default:
				leaf, err := storeUploadedCert(outDir, c.ID, certPEM, chainPEM, keyPEM)
				if err != nil {
					return fmt.Errorf("certificate %d: %w", i+1, err)
				}
				c.Domains = strings.Join(certDomains(leaf), " ")
			}
		}
		certs = append(certs, c)
	}
	g.Certificates = certs
	return g.Validate()
}

// certDomains: the names a certificate is for -- its SANs, or the common
// name when it has none (old-style certificates).
func certDomains(c *x509.Certificate) []string {
	var out []string
	for _, n := range c.DNSNames {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && !strings.ContainsAny(n, " ;{}\"'$#\\") {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		if cn := strings.ToLower(strings.TrimSpace(c.Subject.CommonName)); cn != "" && strings.Contains(cn, ".") && !strings.ContainsAny(cn, " ;{}\"'$#\\") {
			out = append(out, cn)
		}
	}
	return out
}

// storeUploadedCert validates a pasted pair and stores it as the entry's
// files, key readable by the daemon only.  Temp-file + rename, so nginx
// never reads a half-written certificate.  Returns the leaf.
func storeUploadedCert(outDir, id, certPEM, chainPEM, keyPEM string) (*x509.Certificate, error) {
	full := certPEM + "\n"
	if chainPEM != "" {
		full += chainPEM + "\n"
	}
	leaf, err := parseLeafCert(full)
	if err != nil {
		return nil, err
	}
	if _, err := tls.X509KeyPair([]byte(full), []byte(keyPEM+"\n")); err != nil {
		return nil, fmt.Errorf("certificate: the private key does not match the certificate, or is not a PEM key (%v)", err)
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate: expired on %s", leaf.NotAfter.UTC().Format("2006-01-02"))
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return nil, fmt.Errorf("certificate: mkdir %s: %w", outDir, err)
	}
	if err := writePrivate(settings.UploadedKeyPath(outDir, id), []byte(keyPEM+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("certificate: store key: %w", err)
	}
	if err := writePrivate(settings.UploadedCertPath(outDir, id), []byte(full), 0o644); err != nil {
		return nil, fmt.Errorf("certificate: store certificate: %w", err)
	}
	return leaf, nil
}

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

// gatewayCertView: what the gateway's :443 serves for a name, read off the
// wire -- the truth, whatever the settings say.
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

func gatewayCertStatus(addr, serverName string) gatewayCertView {
	v := gatewayCertView{Checked: true}
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // the probe shows whatever :443 serves, self-signed included; verification is the browser's job
	})
	if err != nil {
		v.Err = err.Error()
		return v
	}
	defer func() { _ = conn.Close() }()
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
	if serverName != "" {
		v.NameMatch = c.VerifyHostname(serverName) == nil
	}
	return v
}

// gatewayAddr: where the admin reaches the gateway's :443 (compose: the
// nginx service).
func gatewayAddr() string {
	if a := strings.TrimSpace(os.Getenv("UNMASK_GATEWAY_ADDR")); a != "" {
		return a
	}
	return "nginx:443"
}

// gatewayCertEntryView: one certificate entry of the tab.
type gatewayCertEntryView struct {
	Index    int
	C        settings.GatewayCertificate
	Default  bool // the first: served to any hostname no certificate names
	Cert     gatewayCertView
	Uploaded map[string]any
}

// gatewayCertViews builds the entries; probe = dial :443 per certificate
// with its first domain as SNI (the default without one), only when the tab
// is open.
func gatewayCertViews(g settings.GatewayConfig, outDir string, probe bool) []gatewayCertEntryView {
	g.Normalize()
	var out []gatewayCertEntryView
	for i, c := range g.Certificates {
		row := gatewayCertEntryView{Index: i + 1, C: c, Default: i == 0}
		subj, iss, exp, ok := uploadedCertInfo(outDir, c.ID)
		row.Uploaded = map[string]any{"OK": ok, "Subject": subj, "Issuer": iss, "NotAfter": exp}
		if probe && !g.TLSInFront() {
			row.Cert = gatewayCertStatus(gatewayAddr(), c.FirstDomain())
		}
		out = append(out, row)
	}
	return out
}

func uploadedCertInfo(outDir, id string) (subject, issuer, notAfter string, ok bool) {
	b, err := os.ReadFile(settings.UploadedCertPath(outDir, id))
	if err != nil {
		return "", "", "", false
	}
	c, err := parseLeafCert(string(b))
	if err != nil {
		return "", "", "", false
	}
	return dnLabel(c.Subject), dnLabel(c.Issuer), c.NotAfter.UTC().Format("2006-01-02"), true
}

// gatewayHostnamesText: the custom list, one per line.
func gatewayHostnamesText(g settings.GatewayConfig) string {
	g.Normalize()
	return strings.Join(g.HostnameList(), "\n")
}

// nginxOutDir: where the admin renders, and where uploaded pairs live.
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
