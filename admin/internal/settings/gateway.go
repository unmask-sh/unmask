package settings

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// GatewayConfig: the container gateway (docker/nginx image with
// UNMASK_UPSTREAM set).  Empty on a host install; the settings tab exists
// only while a gateway is configured.
//
// Two independent questions: which hostnames the gateway answers for (all,
// or a list), and which certificates it has -- each certificate knows its
// own domains (typed for Let's Encrypt, read off the SANs of a pasted one).
// The renderer turns that into nginx server blocks: one per certificate,
// named by the certificate's domains, plus a default block that serves the
// first certificate to any other hostname (or rejects the handshake, when
// the hostnames are a list).  TLS may also end in front of the gateway (a
// load balancer forwarding on :80), in which case no :443 server exists.
type GatewayConfig struct {
	// TLS: "" = terminated here, "none" = terminated in front, :80 only.
	TLS string `yaml:"tls,omitempty"`

	Hostnames GatewayHostnames `yaml:"hostnames,omitempty"`

	// The ACME account, shared by every certificate from Let's Encrypt.
	ACMEEmail     string `yaml:"acme_email,omitempty"`
	ACMEDirectory string `yaml:"acme_directory,omitempty"` // "" = Let's Encrypt production
	ACMEInsecure  bool   `yaml:"acme_insecure,omitempty"`  // skip TLS verification of the directory (test servers only)

	// The first certificate is the default: served to any hostname no other
	// certificate names.
	Certificates []GatewayCertificate `yaml:"certificates,omitempty"`

	// Earlier shapes, folded by Normalize on load and never written again:
	// 0.1.37's single vhost, and the vhost list of the 0.1.38 development
	// builds.
	ServerName  string         `yaml:"server_name,omitempty"`
	TLSMode     string         `yaml:"tls_mode,omitempty"`
	TLSCertPath string         `yaml:"tls_cert_path,omitempty"`
	TLSKeyPath  string         `yaml:"tls_key_path,omitempty"`
	Vhosts      []GatewayVhost `yaml:"vhosts,omitempty"`
}

// GatewayHostnames: what the gateway answers for.
type GatewayHostnames struct {
	Mode  string `yaml:"mode,omitempty"`  // "all" | "custom" ("" = all)
	Names string `yaml:"names,omitempty"` // the custom list, space separated
}

// GatewayCertificate: one certificate, and where it comes from.
type GatewayCertificate struct {
	// ID keys the stored pair of a pasted certificate (gateway-<id>.crt);
	// "" is the legacy single pair, gateway.crt.
	ID string `yaml:"id,omitempty"`
	// Mode: acme | upload | files ("" = files).
	Mode string `yaml:"mode,omitempty"`
	// Domains the certificate is for, space separated: what Let's Encrypt
	// issues for; what a pasted certificate's SANs say; what the operator
	// types for a mounted file.  Empty = the certificate serves only as the
	// default.
	Domains  string `yaml:"domains,omitempty"`
	CertPath string `yaml:"cert_path,omitempty"`
	KeyPath  string `yaml:"key_path,omitempty"`
	Title    string `yaml:"title,omitempty"`
}

// GatewayVhost: the 0.1.38 development shape (one row = names + source),
// read only to fold it into Hostnames / Certificates.
type GatewayVhost struct {
	ID       string `yaml:"id,omitempty"`
	Names    string `yaml:"names"`
	TLSMode  string `yaml:"tls_mode,omitempty"`
	CertPath string `yaml:"cert_path,omitempty"`
	KeyPath  string `yaml:"key_path,omitempty"`
	Title    string `yaml:"title,omitempty"`
}

const (
	GatewayTLSACME   = "acme"
	GatewayTLSUpload = "upload"
	GatewayTLSFiles  = "files"
	GatewayTLSNone   = "none" // GatewayConfig.TLS: terminated in front of the gateway; :80 only

	GatewayHostsAll    = "all"
	GatewayHostsCustom = "custom"

	ACMEDirectoryLetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	ACMEDirectoryLetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// Where the compose example mounts a certificate on the nginx container.
	GatewayDefaultCertPath = "/etc/unmask/tls/fullchain.pem"
	GatewayDefaultKeyPath  = "/etc/unmask/tls/privkey.pem"
)

// Normalize folds the earlier shapes into hostnames + certificates.  Called
// on load; a no-op once the config has been saved in the current shape.
func (g *GatewayConfig) Normalize() {
	fields := func(s string) []string { return strings.Fields(strings.ToLower(s)) }
	if strings.TrimSpace(g.TLSMode) == GatewayTLSNone {
		g.TLS = GatewayTLSNone
		g.TLSMode = ""
	}
	if len(g.Vhosts) == 0 && strings.TrimSpace(g.ServerName) != "" {
		g.Vhosts = []GatewayVhost{{Names: g.ServerName, TLSMode: strings.TrimSpace(g.TLSMode), CertPath: strings.TrimSpace(g.TLSCertPath), KeyPath: strings.TrimSpace(g.TLSKeyPath)}}
	}
	if len(g.Vhosts) > 0 && len(g.Certificates) == 0 {
		all := false
		var names []string
		for _, v := range g.Vhosts {
			var domains []string
			for _, n := range fields(v.Names) {
				if n == "_" {
					all = true
					continue
				}
				names = append(names, n)
				domains = append(domains, n)
			}
			g.Certificates = append(g.Certificates, GatewayCertificate{
				ID: v.ID, Mode: strings.TrimSpace(v.TLSMode), Domains: strings.Join(domains, " "),
				CertPath: strings.TrimSpace(v.CertPath), KeyPath: strings.TrimSpace(v.KeyPath), Title: v.Title,
			})
		}
		if all || len(names) == 0 {
			g.Hostnames = GatewayHostnames{Mode: GatewayHostsAll}
		} else {
			g.Hostnames = GatewayHostnames{Mode: GatewayHostsCustom, Names: strings.Join(names, " ")}
		}
	}
	g.ServerName, g.TLSMode, g.TLSCertPath, g.TLSKeyPath, g.Vhosts = "", "", "", "", nil
	if g.Hostnames.Mode == "" && (len(g.Certificates) > 0 || strings.TrimSpace(g.Hostnames.Names) != "") {
		g.Hostnames.Mode = GatewayHostsAll
	}
	g.Hostnames.Names = strings.Join(fields(g.Hostnames.Names), " ")
	for i := range g.Certificates {
		g.Certificates[i].Domains = strings.Join(fields(g.Certificates[i].Domains), " ")
	}
}

// Active: a gateway is configured.
func (g GatewayConfig) Active() bool {
	return g.Hostnames.Mode != "" || len(g.Certificates) > 0 || len(g.Vhosts) > 0 || strings.TrimSpace(g.ServerName) != ""
}

// TLSInFront: TLS is terminated before the gateway; it serves :80 only.
func (g GatewayConfig) TLSInFront() bool {
	return strings.TrimSpace(g.TLS) == GatewayTLSNone || strings.TrimSpace(g.TLSMode) == GatewayTLSNone
}

// HostnamesAll: the gateway answers for any hostname.
func (g GatewayConfig) HostnamesAll() bool { return g.Hostnames.Mode != GatewayHostsCustom }

// HostnameList: the custom list.
func (g GatewayConfig) HostnameList() []string {
	return strings.Fields(strings.ToLower(g.Hostnames.Names))
}

// UsesACME: at least one certificate comes from the ACME account.
func (g GatewayConfig) UsesACME() bool {
	if g.TLSInFront() {
		return false
	}
	for _, c := range g.Certificates {
		if c.ModeResolved() == GatewayTLSACME {
			return true
		}
	}
	return false
}

// ACMEDirectoryResolved: empty means Let's Encrypt production.
func (g GatewayConfig) ACMEDirectoryResolved() string {
	if strings.TrimSpace(g.ACMEDirectory) == "" {
		return ACMEDirectoryLetsEncrypt
	}
	return strings.TrimSpace(g.ACMEDirectory)
}

// Uncovered: custom hostnames no certificate names (they get the default
// certificate, and a browser warning).  A default certificate without
// domains (a mounted file, the single-certificate case) is taken to be for
// every hostname, so nothing is uncovered then.
func (g GatewayConfig) Uncovered() []string {
	if g.HostnamesAll() || len(g.Certificates) == 0 || len(g.Certificates[0].DomainList()) == 0 {
		return nil
	}
	covered := map[string]bool{}
	for _, c := range g.Certificates {
		for _, d := range c.DomainList() {
			covered[d] = true
		}
	}
	var out []string
	for _, n := range g.HostnameList() {
		if !covered[n] {
			out = append(out, n)
		}
	}
	return out
}

// NewCertificateID mints the stable key of a certificate's stored pair.
func NewCertificateID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "c"
	}
	return hex.EncodeToString(b)
}

// DomainList splits the certificate's domains.
func (c GatewayCertificate) DomainList() []string { return strings.Fields(strings.ToLower(c.Domains)) }

// FirstDomain is the name a probe uses as SNI ("" when there is none).
func (c GatewayCertificate) FirstDomain() string {
	for _, d := range c.DomainList() {
		if !strings.ContainsAny(d, "*~") {
			return d
		}
	}
	return ""
}

// ModeResolved folds the empty value onto files.
func (c GatewayCertificate) ModeResolved() string {
	switch c.Mode {
	case GatewayTLSACME, GatewayTLSUpload:
		return c.Mode
	}
	return GatewayTLSFiles
}

// UploadedCertPath / UploadedKeyPath: where a pasted pair is stored, beside
// the rendered includes (not under tls/, which a compose file may bind-mount
// over on the nginx side).  id "" is the legacy single pair.
func UploadedCertPath(outDir, id string) string {
	if id == "" {
		return filepath.Join(outDir, "gateway.crt")
	}
	return filepath.Join(outDir, "gateway-"+id+".crt")
}

func UploadedKeyPath(outDir, id string) string {
	if id == "" {
		return filepath.Join(outDir, "gateway.key")
	}
	return filepath.Join(outDir, "gateway-"+id+".key")
}

// CertPathResolved / KeyPathResolved: the files nginx reads, for upload and
// files modes (ACME manages its own).
func (c GatewayCertificate) CertPathResolved(outDir string) string {
	if c.ModeResolved() == GatewayTLSUpload {
		return UploadedCertPath(outDir, c.ID)
	}
	if p := strings.TrimSpace(c.CertPath); p != "" {
		return p
	}
	return GatewayDefaultCertPath
}

func (c GatewayCertificate) KeyPathResolved(outDir string) string {
	if c.ModeResolved() == GatewayTLSUpload {
		return UploadedKeyPath(outDir, c.ID)
	}
	if p := strings.TrimSpace(c.KeyPath); p != "" {
		return p
	}
	return GatewayDefaultKeyPath
}

func hostnameOK(label, name string) error {
	if err := nginxToken(label, name); err != nil {
		return err
	}
	for _, r := range name {
		if !(r == '.' || r == '-' || r == '_' || r == '*' || r == '~' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("%s: unexpected character %q", label, r)
		}
	}
	return nil
}

// Validate: the values land inside rendered nginx directives, so first of
// all nothing may end a directive; then each part's own requirements.
func (g GatewayConfig) Validate() error {
	n := g
	n.Normalize()
	if !n.Active() {
		return nil
	}
	switch n.Hostnames.Mode {
	case GatewayHostsAll:
	case GatewayHostsCustom:
		names := n.HostnameList()
		if len(names) == 0 {
			return errors.New("hostnames: the custom list needs at least one hostname")
		}
		for _, name := range names {
			if name == "_" {
				return errors.New("hostnames: \"_\" is not a hostname -- choose \"all hostnames\" instead")
			}
			if err := hostnameOK("hostname", name); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("hostnames: unknown mode %q", n.Hostnames.Mode)
	}
	if n.TLSInFront() {
		return nil
	}
	if len(n.Certificates) == 0 {
		return errors.New("certificates: at least one certificate is required (it is what :443 serves)")
	}
	seen := map[string]int{}
	for i, c := range n.Certificates {
		if err := nginxToken("certificate id", "x"+c.ID); err != nil {
			return fmt.Errorf("certificate %d: %w", i+1, err)
		}
		if strings.ContainsAny(c.ID, "/.") {
			return fmt.Errorf("certificate %d: id must not contain '/' or '.'", i+1)
		}
		domains := c.DomainList()
		for _, d := range domains {
			if d == "_" {
				return fmt.Errorf("certificate %d: \"_\" is not a domain -- the first certificate is the default already", i+1)
			}
			if err := hostnameOK("domain", d); err != nil {
				return fmt.Errorf("certificate %d: %w", i+1, err)
			}
			if j, dup := seen[d]; dup {
				return fmt.Errorf("certificate %d: %s is already on certificate %d", i+1, d, j+1)
			}
			seen[d] = i
		}
		switch c.ModeResolved() {
		case GatewayTLSACME:
			if len(domains) == 0 {
				return fmt.Errorf("certificate %d: Let's Encrypt needs the domains to issue for", i+1)
			}
			for _, d := range domains {
				if strings.ContainsAny(d, "*~") {
					return fmt.Errorf("certificate %d: Let's Encrypt issues for real names only (no wildcard, no regex)", i+1)
				}
			}
		case GatewayTLSFiles:
			for label, p := range map[string]string{"certificate path": c.CertPathResolved(""), "key path": c.KeyPathResolved("")} {
				if err := nginxToken(label, p); err != nil {
					return fmt.Errorf("certificate %d: %w", i+1, err)
				}
				if !strings.HasPrefix(p, "/") {
					return fmt.Errorf("certificate %d: %s: must be absolute", i+1, label)
				}
			}
		}
	}
	if n.UsesACME() {
		email := strings.TrimSpace(n.ACMEEmail)
		if email == "" {
			return errors.New("ACME: a contact e-mail address is required")
		}
		if err := nginxToken("ACME e-mail", email); err != nil {
			return err
		}
		if !strings.Contains(email, "@") || strings.ContainsAny(email, "/:") {
			return errors.New("ACME: the contact must be a plain e-mail address")
		}
		dir := n.ACMEDirectoryResolved()
		if err := nginxToken("ACME directory", dir); err != nil {
			return err
		}
		u, err := url.Parse(dir)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("ACME: the directory must be an https:// URL")
		}
	}
	return nil
}

// nginxToken rejects anything that could end the directive the value is
// rendered into: separators, quotes, comments, variables, line breaks.
func nginxToken(label, v string) error {
	if v == "" {
		return fmt.Errorf("%s: required", label)
	}
	if strings.ContainsAny(v, ";{}\"'\n\r\t #$\\") {
		return fmt.Errorf("%s: must not contain spaces, quotes, ';', '#', '$' or braces", label)
	}
	return nil
}
