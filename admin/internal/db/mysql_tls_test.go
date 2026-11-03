package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func mariaSection(tlsMode string) settings.DB {
	return settings.DB{Driver: "mariadb", MariaDB: settings.MariaDB{Host: "db.example", Port: 3306, User: "u", Password: "p", Database: "unmask"}, MySQLTLS: tlsMode}
}

// db.mysql_tls: "" is the plain connection every release made; the
// driver's words pass through; a path is the CA the server's certificate is
// checked against, with the server's name from mariadb.host; and a path
// that is not a CA is refused at the open.
func TestMariaDBConfigTLS(t *testing.T) {
	for mode, want := range map[string]string{"": "", "false": "", "true": "true", " TRUE ": "true", "skip-verify": "skip-verify", "preferred": "preferred"} {
		cfg, err := mariaDBConfig(mariaSection(mode))
		if err != nil {
			t.Fatalf("mysql_tls %q: %v", mode, err)
		}
		if cfg.TLSConfig != want {
			t.Errorf("mysql_tls %q: TLSConfig = %q, want %q", mode, cfg.TLSConfig, want)
		}
		dsn := cfg.FormatDSN()
		if want == "" && strings.Contains(dsn, "tls=") {
			t.Errorf("mysql_tls %q: the DSN names tls: %s", mode, dsn)
		}
		if want != "" && !strings.Contains(dsn, "tls="+want) {
			t.Errorf("mysql_tls %q: the DSN lacks tls=%s: %s", mode, want, dsn)
		}
		if !strings.Contains(dsn, "time_zone=") || !strings.Contains(dsn, "tcp(db.example:3306)") {
			t.Errorf("mysql_tls %q: the rest of the DSN changed: %s", mode, dsn)
		}
	}

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, selfSignedCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := mariaDBConfig(mariaSection(ca))
	if err != nil {
		t.Fatalf("CA file: %v", err)
	}
	if cfg.TLSConfig != mysqlCAConfigName || !strings.Contains(cfg.FormatDSN(), "tls="+mysqlCAConfigName) {
		t.Errorf("CA file: TLSConfig = %q, DSN %s", cfg.TLSConfig, cfg.FormatDSN())
	}
	// The driver resolves the name when it reads the DSN.
	parsed, err := mysql.ParseDSN(cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TLS == nil || parsed.TLS.RootCAs == nil || parsed.TLS.ServerName != "db.example" {
		t.Errorf("CA file: the registered configuration is %+v", parsed.TLS)
	}

	if _, err := mariaDBConfig(mariaSection(filepath.Join(dir, "none.pem"))); err == nil || !strings.Contains(err.Error(), "db.mysql_tls") {
		t.Errorf("a missing file: %v", err)
	}
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mariaDBConfig(mariaSection(notPEM)); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("a file without a certificate: %v", err)
	}

	// The section's identity for "is it the same database" counts the TLS
	// setting: a change of it is a change of connection.
	if mariaSection("true").Connection() == mariaSection("").Connection() {
		t.Error("Connection() ignores mysql_tls")
	}
}

func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unmask test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
