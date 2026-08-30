package settings

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// GatewayConfig describes the container gateway -- the unmask nginx image
// terminating TLS in front of an upstream -- as far as the admin owns it:
// the hostname it answers for and where its certificate comes from.  The
// admin renders these into gateway-*.inc next to the other includes, and
// the nginx container's gateway template pulls them in; its own reload
// watcher applies a change within seconds.
//
// Deliberately narrow.  What the gateway proxies TO stays an environment
// variable on the nginx container (UNMASK_UPSTREAM): that is deployment
// wiring, not a setting, and keeping it out of the UI means an admin
// session cannot repoint a site's traffic.  Anything beyond one vhost --
// several hostnames with separate certificates, custom nginx directives --
// is module-only territory, where the operator writes the conf.
//
// Empty ServerName means "no gateway": nothing is rendered and the tab
// stays out of the settings menu, so a host install never sees this.
type GatewayConfig struct {
	// ServerName: the nginx server_name of the gateway vhost.  "_" answers
	// for any name (fine with your own certificate; useless for ACME).
	ServerName string `yaml:"server_name,omitempty"`
	// TLSMode: where the certificate comes from.
	//   acme   -- nginx's ACME module obtains and renews it (Let's Encrypt).
	//   upload -- a certificate pasted into the admin UI, stored under the
	//             render directory (gateway.crt + gateway.key; not under tls/, which
	//             a compose file may bind-mount over on the nginx side).
	//   files  -- files the operator mounted, at TLSCertPath / TLSKeyPath.
	// Empty reads as files, which is what an env-seeded container starts on.
	TLSMode       string `yaml:"tls_mode,omitempty"`
	ACMEEmail     string `yaml:"acme_email,omitempty"`
	ACMEDirectory string `yaml:"acme_directory,omitempty"`
	// ACMEInsecure skips verification of the ACME server's own certificate.
	// Only for a private test server (Pebble); never for Let's Encrypt.
	ACMEInsecure bool   `yaml:"acme_insecure,omitempty"`
	TLSCertPath  string `yaml:"tls_cert_path,omitempty"`
	TLSKeyPath   string `yaml:"tls_key_path,omitempty"`
}

const (
	GatewayTLSACME   = "acme"
	GatewayTLSUpload = "upload"
	GatewayTLSFiles  = "files"
	GatewayTLSNone   = "none" // TLS terminated in front of the gateway (a load balancer); :80 only

	ACMEDirectoryLetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	ACMEDirectoryLetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// Where the gateway image mounts operator-provided files by default.
	GatewayDefaultCertPath = "/etc/unmask/tls/fullchain.pem"
	GatewayDefaultKeyPath  = "/etc/unmask/tls/privkey.pem"
)

// Active reports whether a gateway is configured at all.
func (g GatewayConfig) Active() bool { return strings.TrimSpace(g.ServerName) != "" }

// ServerNames splits the configured name list (space separated).
func (g GatewayConfig) ServerNames() []string { return strings.Fields(g.ServerName) }

// TLSModeResolved folds the empty value onto files.
func (g GatewayConfig) TLSModeResolved() string {
	switch g.TLSMode {
	case GatewayTLSACME, GatewayTLSUpload, GatewayTLSNone:
		return g.TLSMode
	}
	return GatewayTLSFiles
}

// ACMEDirectoryResolved: empty means Let's Encrypt production.
func (g GatewayConfig) ACMEDirectoryResolved() string {
	if strings.TrimSpace(g.ACMEDirectory) == "" {
		return ACMEDirectoryLetsEncrypt
	}
	return strings.TrimSpace(g.ACMEDirectory)
}

// UploadedCertPath / UploadedKeyPath: where a pasted certificate is kept.
// Under the render directory so the nginx container sees it through the same
// shared volume as the includes.
func UploadedCertPath(outDir string) string { return filepath.Join(outDir, "gateway.crt") }
func UploadedKeyPath(outDir string) string  { return filepath.Join(outDir, "gateway.key") }

// CertPathResolved / KeyPathResolved: the paths the rendered vhost points
// at for the non-ACME modes.
func (g GatewayConfig) CertPathResolved(outDir string) string {
	switch g.TLSModeResolved() {
	case GatewayTLSUpload:
		return UploadedCertPath(outDir)
	}
	if p := strings.TrimSpace(g.TLSCertPath); p != "" {
		return p
	}
	return GatewayDefaultCertPath
}

func (g GatewayConfig) KeyPathResolved(outDir string) string {
	switch g.TLSModeResolved() {
	case GatewayTLSUpload:
		return UploadedKeyPath(outDir)
	}
	if p := strings.TrimSpace(g.TLSKeyPath); p != "" {
		return p
	}
	return GatewayDefaultKeyPath
}

// Validate checks the fields as nginx will see them.  Every value here ends
// up inside a rendered directive, so the check is as much about what a
// value must not contain (a `;`, a `{`, a newline -- anything that would
// end the directive early and start another) as about what it should.
func (g GatewayConfig) Validate() error {
	if !g.Active() {
		return nil
	}
	// One or more names, space separated (nginx's server_name takes a list;
	// ACME issues one certificate covering all of them).
	names := g.ServerNames()
	for _, name := range names {
		if err := nginxToken("hostname", name); err != nil {
			return err
		}
		for _, r := range name {
			if !(r == '.' || r == '-' || r == '_' || r == '*' || r == '~' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
				return fmt.Errorf("hostname: unexpected character %q", r)
			}
		}
	}
	switch g.TLSModeResolved() {
	case GatewayTLSACME:
		email := strings.TrimSpace(g.ACMEEmail)
		if email == "" {
			return errors.New("ACME: a contact e-mail address is required")
		}
		if err := nginxToken("ACME e-mail", email); err != nil {
			return err
		}
		if !strings.Contains(email, "@") || strings.ContainsAny(email, "/:") {
			return errors.New("ACME: the contact must be a plain e-mail address")
		}
		for _, n := range names {
			if n == "_" || strings.ContainsAny(n, "*~") {
				return errors.New("ACME: every hostname must be a real name -- the certificate is issued for them (no catch-all, no wildcard)")
			}
		}
		dir := g.ACMEDirectoryResolved()
		if err := nginxToken("ACME directory", dir); err != nil {
			return err
		}
		u, err := url.Parse(dir)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("ACME: the directory must be an https:// URL")
		}
	case GatewayTLSFiles:
		for label, p := range map[string]string{"certificate path": g.CertPathResolved(""), "key path": g.KeyPathResolved("")} {
			if err := nginxToken(label, p); err != nil {
				return err
			}
			if !strings.HasPrefix(p, "/") {
				return fmt.Errorf("%s: must be absolute", label)
			}
		}
	}
	return nil
}

// nginxToken rejects anything that could not sit inside one nginx
// directive as a single value.
func nginxToken(label, v string) error {
	if v == "" {
		return fmt.Errorf("%s: required", label)
	}
	if strings.ContainsAny(v, ";{}\"'\n\r\t #$\\") {
		return fmt.Errorf("%s: must not contain spaces, quotes, ';', '#', '$' or braces", label)
	}
	return nil
}
