package nginxconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// selfSignedOrg marks the pairs this code generated; only those are ever
// judged current and regenerated -- a pasted certificate stored under the
// same id is left alone.
const selfSignedOrg = "unmask gateway (self-signed)"

// ensureGatewaySelfSigned materializes the pair of every self-signed
// certificate entry (settings > Gateway): generated on the first render, so
// the gateway's :443 starts with nothing configured and the operator can
// reach the admin over https to set up Let's Encrypt or paste a
// certificate; regenerated when the names it should carry change, kept
// otherwise (the browser exception the operator clicked through survives).
func ensureGatewaySelfSigned(s settings.Settings, outDir string) error {
	g := s.Gateway
	g.Normalize()
	if !g.Active() || g.TLSInFront() {
		return nil
	}
	for _, c := range g.Certificates {
		if c.ModeResolved() != settings.GatewayTLSSelfSigned {
			continue
		}
		names := g.SelfSignedNames(c)
		certPath, keyPath := c.CertPathResolved(outDir), c.KeyPathResolved(outDir)
		if selfSignedCurrent(certPath, keyPath, names) {
			continue
		}
		if err := writeSelfSigned(certPath, keyPath, names); err != nil {
			return fmt.Errorf("self-signed certificate: %w", err)
		}
	}
	return nil
}

// selfSignedCurrent: the pair exists, is ours, carries exactly the wanted
// names, and is not about to expire.
func selfSignedCurrent(certPath, keyPath string, names []string) bool {
	b, err := os.ReadFile(certPath) //nolint:gosec // the render directory's own file
	if err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if len(c.Subject.Organization) == 0 || c.Subject.Organization[0] != selfSignedOrg {
		return false
	}
	if time.Until(c.NotAfter) < 30*24*time.Hour {
		return false
	}
	var got []string
	got = append(got, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		got = append(got, ip.String())
	}
	want := append([]string(nil), names...)
	sort.Strings(got)
	sort.Strings(want)
	return strings.Join(got, " ") == strings.Join(want, " ")
}

func writeSelfSigned(certPath, keyPath string, names []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0], Organization: []string{selfSignedOrg}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// writeFileAtomic: temp file + rename, so nginx never reads a half-written
// certificate.
func writeFileAtomic(path string, b []byte, perm os.FileMode) error {
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
