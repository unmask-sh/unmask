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
// only while at least one vhost is configured.
//
// The gateway is a list of vhosts, each with its own names and its own
// certificate source, rendered as one :443 server block each -- nginx picks
// the block by SNI, which is how one gateway serves several sites with
// several certificates.  TLS may also end in front of the gateway (a load
// balancer forwarding on :80), in which case no :443 server exists at all.
type GatewayConfig struct {
	// TLS: "" = terminated here (the vhosts below carry the certificates),
	// "none" = terminated in front, :80 only.
	TLS string `yaml:"tls,omitempty"`

	// The ACME account, shared by every vhost that uses Let's Encrypt.
	ACMEEmail     string `yaml:"acme_email,omitempty"`
	ACMEDirectory string `yaml:"acme_directory,omitempty"` // "" = Let's Encrypt production
	ACMEInsecure  bool   `yaml:"acme_insecure,omitempty"`  // skip TLS verification of the directory (test servers only)

	Vhosts []GatewayVhost `yaml:"vhosts,omitempty"`

	// The 0.1.37 single-vhost shape.  Read once by Normalize (which folds it
	// into Vhosts / TLS); a save from 0.1.38 on writes only the fields above.
	ServerName  string `yaml:"server_name,omitempty"`
	TLSMode     string `yaml:"tls_mode,omitempty"`
	TLSCertPath string `yaml:"tls_cert_path,omitempty"`
	TLSKeyPath  string `yaml:"tls_key_path,omitempty"`
}

// GatewayVhost: one :443 server block.
type GatewayVhost struct {
	// ID keys the stored pair of an uploaded certificate (gateway-<id>.crt).
	// The first vhost of a migrated 0.1.37 config keeps "" and the legacy
	// gateway.crt, so a stored pair survives the upgrade.
	ID       string `yaml:"id,omitempty"`
	Names    string `yaml:"names"`              // space separated; "_" answers for any name
	TLSMode  string `yaml:"tls_mode,omitempty"` // acme | upload | files ("" = files)
	CertPath string `yaml:"cert_path,omitempty"`
	KeyPath  string `yaml:"key_path,omitempty"`
	Title    string `yaml:"title,omitempty"`
}

const (
	GatewayTLSACME   = "acme"
	GatewayTLSUpload = "upload"
	GatewayTLSFiles  = "files"
	GatewayTLSNone   = "none" // GatewayConfig.TLS: terminated in front of the gateway; :80 only

	ACMEDirectoryLetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	ACMEDirectoryLetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// Where the compose example mounts a certificate on the nginx container.
	GatewayDefaultCertPath = "/etc/unmask/tls/fullchain.pem"
	GatewayDefaultKeyPath  = "/etc/unmask/tls/privkey.pem"
)

// Normalize folds the 0.1.37 single-vhost fields into the list form.  Called
// on load; a no-op once the config has been saved in the new shape.
func (g *GatewayConfig) Normalize() {
	if len(g.Vhosts) == 0 && strings.TrimSpace(g.ServerName) != "" {
		mode := strings.TrimSpace(g.TLSMode)
		if mode == GatewayTLSNone {
			g.TLS = GatewayTLSNone
			mode = ""
		}
		g.Vhosts = []GatewayVhost{{
			Names:    strings.Join(strings.Fields(g.ServerName), " "),
			TLSMode:  mode,
			CertPath: strings.TrimSpace(g.TLSCertPath),
			KeyPath:  strings.TrimSpace(g.TLSKeyPath),
		}}
	}
	g.ServerName, g.TLSMode, g.TLSCertPath, g.TLSKeyPath = "", "", "", ""
	for i := range g.Vhosts {
		g.Vhosts[i].Names = strings.Join(strings.Fields(g.Vhosts[i].Names), " ")
	}
}

// Active: a gateway is configured.
func (g GatewayConfig) Active() bool {
	if len(g.Vhosts) > 0 {
		return true
	}
	return strings.TrimSpace(g.ServerName) != ""
}

// TLSInFront: TLS is terminated before the gateway; it serves :80 only.
func (g GatewayConfig) TLSInFront() bool {
	return strings.TrimSpace(g.TLS) == GatewayTLSNone || strings.TrimSpace(g.TLSMode) == GatewayTLSNone
}

// UsesACME: at least one vhost is issued by the ACME account.
func (g GatewayConfig) UsesACME() bool {
	if g.TLSInFront() {
		return false
	}
	for _, v := range g.Vhosts {
		if v.ModeResolved() == GatewayTLSACME {
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

// NewVhostID mints the stable key of a vhost's stored pair.
func NewVhostID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "v"
	}
	return hex.EncodeToString(b)
}

// NameList splits the vhost's names.
func (v GatewayVhost) NameList() []string { return strings.Fields(v.Names) }

// FirstName is the name a probe uses as SNI ("" for a catch-all).
func (v GatewayVhost) FirstName() string {
	for _, n := range v.NameList() {
		if n != "_" && !strings.ContainsAny(n, "*~") {
			return n
		}
	}
	return ""
}

// CatchAll: answers for any name (nginx's "_").
func (v GatewayVhost) CatchAll() bool {
	for _, n := range v.NameList() {
		if n == "_" {
			return true
		}
	}
	return false
}

// ModeResolved folds the empty value onto files.
func (v GatewayVhost) ModeResolved() string {
	switch v.TLSMode {
	case GatewayTLSACME, GatewayTLSUpload:
		return v.TLSMode
	}
	return GatewayTLSFiles
}

// UploadedCertPath / UploadedKeyPath: where a pasted pair is stored, beside
// the rendered includes (not under tls/, which a compose file may bind-mount
// over on the nginx side).  id "" is the legacy single-vhost pair.
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
func (v GatewayVhost) CertPathResolved(outDir string) string {
	if v.ModeResolved() == GatewayTLSUpload {
		return UploadedCertPath(outDir, v.ID)
	}
	if p := strings.TrimSpace(v.CertPath); p != "" {
		return p
	}
	return GatewayDefaultCertPath
}

func (v GatewayVhost) KeyPathResolved(outDir string) string {
	if v.ModeResolved() == GatewayTLSUpload {
		return UploadedKeyPath(outDir, v.ID)
	}
	if p := strings.TrimSpace(v.KeyPath); p != "" {
		return p
	}
	return GatewayDefaultKeyPath
}

// Validate: the values land inside rendered nginx directives, so first of
// all nothing may end a directive; then each mode's own requirements.
func (g GatewayConfig) Validate() error {
	n := g
	n.Normalize()
	if !n.Active() {
		return nil
	}
	seen := map[string]int{}
	for i, v := range n.Vhosts {
		names := v.NameList()
		if len(names) == 0 {
			return fmt.Errorf("vhost %d: at least one hostname is required", i+1)
		}
		for _, name := range names {
			if err := nginxToken("hostname", name); err != nil {
				return fmt.Errorf("vhost %d: %w", i+1, err)
			}
			for _, r := range name {
				if !(r == '.' || r == '-' || r == '_' || r == '*' || r == '~' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
					return fmt.Errorf("vhost %d: hostname: unexpected character %q", i+1, r)
				}
			}
			if j, dup := seen[strings.ToLower(name)]; dup {
				return fmt.Errorf("vhost %d: %s is already served by vhost %d", i+1, name, j+1)
			}
			seen[strings.ToLower(name)] = i
		}
		if err := nginxToken("vhost id", "x"+v.ID); err != nil {
			return fmt.Errorf("vhost %d: %w", i+1, err)
		}
		if strings.ContainsAny(v.ID, "/.") {
			return fmt.Errorf("vhost %d: id must not contain '/' or '.'", i+1)
		}
		if n.TLSInFront() {
			continue
		}
		switch v.ModeResolved() {
		case GatewayTLSACME:
			for _, name := range names {
				if name == "_" || strings.ContainsAny(name, "*~") {
					return fmt.Errorf("vhost %d: ACME: every hostname must be a real name -- the certificate is issued for them (no catch-all, no wildcard)", i+1)
				}
			}
		case GatewayTLSFiles:
			for label, p := range map[string]string{"certificate path": v.CertPathResolved(""), "key path": v.KeyPathResolved("")} {
				if err := nginxToken(label, p); err != nil {
					return fmt.Errorf("vhost %d: %w", i+1, err)
				}
				if !strings.HasPrefix(p, "/") {
					return fmt.Errorf("vhost %d: %s: must be absolute", i+1, label)
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
