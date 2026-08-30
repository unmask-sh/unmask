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

// applyGatewayForm reads settings > Gateway.  The tab is two lists: the
// hostnames the gateway answers for (a textarea plus a catch-all box), and
// the certificates, each covering some of those names.  A certificate is
// one vhost; the covered names travel in a hidden cert_names the chips
// maintain, and every name must sit on exactly one certificate.  Entries
// are parallel arrays in DOM order (a <select> per entry, never a checkbox).
// A pasted pair is checked and stored under the entry's id before the
// config is validated, so a bad paste never reaches the render.
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

	// The names, deduplicated, lower-cased, in the order given; "_" is the
	// catch-all box, never a typed name.
	var names []string
	seen := map[string]bool{}
	for _, n := range strings.Fields(strings.ToLower(r.FormValue("hostnames"))) {
		if n == "_" || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	catchAll := r.FormValue("catch_all") == "1"
	if len(names) == 0 && !catchAll {
		return errors.New("hostnames: enter at least one hostname, or answer for any hostname")
	}
	if catchAll {
		names = append(names, "_")
	}

	// TLS in front: no certificates; one vhost naming everything is enough
	// (the :80 server is a catch-all anyway, the list just records intent).
	if g.TLSInFront() {
		id := ""
		if len(g.Vhosts) > 0 {
			id = g.Vhosts[0].ID
		}
		g.Vhosts = []settings.GatewayVhost{{ID: id, Names: strings.Join(names, " ")}}
		return g.Validate()
	}

	col := func(k string) []string { return r.Form[k] }
	ids, covered, modes := col("cert_id"), col("cert_names"), col("cert_mode")
	certPaths, keyPaths := col("cert_cert_path"), col("cert_key_path")
	certPEMs, chainPEMs, keyPEMs := col("cert_cert_pem"), col("cert_chain_pem"), col("cert_key_pem")
	at := func(a []string, i int) string {
		if i < len(a) {
			return strings.TrimSpace(a[i])
		}
		return ""
	}
	n := len(modes)
	if n == 0 {
		return errors.New("certificates: add a certificate for the hostnames above")
	}
	owner := map[string]int{}
	var vhosts []settings.GatewayVhost
	for i := 0; i < n; i++ {
		v := settings.GatewayVhost{ID: at(ids, i)}
		if v.ID == "" && i > 0 {
			v.ID = settings.NewVhostID()
		}
		var mine []string
		for _, c := range strings.Fields(strings.ToLower(at(covered, i))) {
			if !seen[c] && !(c == "_" && catchAll) {
				continue // a name that is no longer in the list
			}
			if j, taken := owner[c]; taken {
				return fmt.Errorf("certificate %d: %s is already on certificate %d", i+1, c, j+1)
			}
			owner[c] = i
			mine = append(mine, c)
		}
		if len(mine) == 0 {
			return fmt.Errorf("certificate %d: pick at least one hostname for it", i+1)
		}
		v.Names = strings.Join(mine, " ")
		mode := at(modes, i)
		switch mode {
		case settings.GatewayTLSACME, settings.GatewayTLSUpload, settings.GatewayTLSFiles:
		case "":
			mode = settings.GatewayTLSFiles
		default:
			return fmt.Errorf("certificate %d: unknown source %q", i+1, mode)
		}
		v.TLSMode = mode
		v.CertPath = at(certPaths, i)
		v.KeyPath = at(keyPaths, i)
		if mode == settings.GatewayTLSUpload {
			certPEM, chainPEM, keyPEM := at(certPEMs, i), at(chainPEMs, i), at(keyPEMs, i)
			switch {
			case certPEM == "" && keyPEM == "":
				if _, err := os.Stat(settings.UploadedCertPath(outDir, v.ID)); err != nil {
					return fmt.Errorf("certificate %d: paste the certificate and its private key (none is stored yet)", i+1)
				}
			case certPEM == "" || keyPEM == "":
				return fmt.Errorf("certificate %d: paste both the certificate and the private key", i+1)
			default:
				if err := storeUploadedCert(outDir, v.ID, certPEM, chainPEM, keyPEM); err != nil {
					return fmt.Errorf("certificate %d: %w", i+1, err)
				}
			}
		}
		vhosts = append(vhosts, v)
	}
	var uncovered []string
	for _, nm := range names {
		if _, ok := owner[nm]; !ok {
			if nm == "_" {
				nm = "(any other hostname)"
			}
			uncovered = append(uncovered, nm)
		}
	}
	if len(uncovered) > 0 {
		return fmt.Errorf("hostnames with no certificate: %s", strings.Join(uncovered, ", "))
	}
	g.Vhosts = vhosts
	return g.Validate()
}

// storeUploadedCert validates a pasted pair and stores it as the vhost's
// files, key readable by the daemon only.  Temp-file + rename, so nginx
// never reads a half-written certificate.
func storeUploadedCert(outDir, id, certPEM, chainPEM, keyPEM string) error {
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
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return fmt.Errorf("certificate: mkdir %s: %w", outDir, err)
	}
	if err := writePrivate(settings.UploadedKeyPath(outDir, id), []byte(keyPEM+"\n"), 0o600); err != nil {
		return fmt.Errorf("certificate: store key: %w", err)
	}
	if err := writePrivate(settings.UploadedCertPath(outDir, id), []byte(full), 0o644); err != nil {
		return fmt.Errorf("certificate: store certificate: %w", err)
	}
	return nil
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

// gatewayCertView: what the gateway's :443 serves for one vhost, read off
// the wire -- the truth, whatever the settings say.
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

// gatewayVhostView: one row of the tab.
type gatewayVhostView struct {
	Index    int
	V        settings.GatewayVhost
	Any      bool // catch-all row
	Cert     gatewayCertView
	Uploaded map[string]any
}

// gatewayVhostViews builds the rows; probe = dial :443 per vhost (the tab is
// the only place that happens).
func gatewayVhostViews(g settings.GatewayConfig, outDir string, probe bool) []gatewayVhostView {
	g.Normalize()
	var out []gatewayVhostView
	for i, v := range g.Vhosts {
		row := gatewayVhostView{Index: i + 1, V: v, Any: v.CatchAll()}
		subj, iss, exp, ok := uploadedCertInfo(outDir, v.ID)
		row.Uploaded = map[string]any{"OK": ok, "Subject": subj, "Issuer": iss, "NotAfter": exp}
		if probe && !g.TLSInFront() {
			row.Cert = gatewayCertStatus(gatewayAddr(), v.FirstName())
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

// gatewayNamesText: the hostnames card, one per line, the catch-all left
// to its checkbox.
func gatewayNamesText(g settings.GatewayConfig) string {
	g.Normalize()
	var out []string
	for _, v := range g.Vhosts {
		for _, n := range v.NameList() {
			if n != "_" {
				out = append(out, n)
			}
		}
	}
	return strings.Join(out, "\n")
}

func gatewayCatchAll(g settings.GatewayConfig) bool {
	g.Normalize()
	for _, v := range g.Vhosts {
		if v.CatchAll() {
			return true
		}
	}
	return false
}
