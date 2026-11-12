package nginxconf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestNginxJudgesAnUntrustedHeaderByTheConnection runs a real nginx with the
// module over the rendered http.inc and asks it what fingerprint it judges a
// request by.
//
// With a trusted-LB preset on, a JA4 header from an address outside the
// trusted set is whatever the client wrote.  Every such request used to be
// given the sentinel "NOT_TRUSTED", which no JA4 rule and no "<ip>|<ja4>" ban
// matches: a client that reached the origin past the load balancer took
// itself out of all of them with one header.  It is judged by its own
// connection's fingerprint now, as if the header were not there; the
// sentinel is left for a connection that has none (plain HTTP).
//
// Skipped unless UNMASK_TEST_NGINX and UNMASK_TEST_NGINX_MODULE are set (the
// fingerprint is the module's): `make test-nginx-accepts` sets both.
func TestNginxJudgesAnUntrustedHeaderByTheConnection(t *testing.T) {
	bin, mod := os.Getenv("UNMASK_TEST_NGINX"), os.Getenv("UNMASK_TEST_NGINX_MODULE")
	if bin == "" || mod == "" {
		t.Skip("UNMASK_TEST_NGINX / UNMASK_TEST_NGINX_MODULE are not set")
	}

	// ask starts nginx on the render of yaml and returns what it says of a
	// request: "<the fingerprint it judges by>|<the trust diagnosis>".
	type asker func(tlsConn bool, header string) string
	start := func(t *testing.T, yaml string) asker {
		t.Helper()
		dir := t.TempDir()
		s, err := settings.LoadFromYAML("secret:\n  bv_secret: \"0123456789abcdef0123456789abcdef\"\nnginx_log:\n  enabled: false\ncommunity_bans:\n  subscribe_mode: \"off\"\n" + yaml)
		if err != nil {
			t.Fatalf("config.yml: %v", err)
		}
		certPath, keyPath := selfSigned(t, dir)
		plainPort, tlsPort := freePort(t), freePort(t)
		var b strings.Builder
		b.WriteString("load_module " + mod + ";\n")
		b.WriteString("daemon off;\nmaster_process off;\npid " + dir + "/nginx.pid;\nerror_log " + dir + "/error.log notice;\nevents { worker_connections 64; }\nhttp {\n")
		for _, p := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
			b.WriteString("    " + p + "_temp_path " + dir + "/tmp-" + p + ";\n")
		}
		b.WriteString("    access_log off;\n")
		b.WriteString("    include " + dir + "/http.inc;\n")
		b.WriteString("    server {\n")
		fmt.Fprintf(&b, "        listen 127.0.0.1:%d;\n        listen 127.0.0.1:%d ssl;\n", plainPort, tlsPort)
		b.WriteString("        ssl_certificate " + certPath + ";\n        ssl_certificate_key " + keyPath + ";\n")
		b.WriteString("        server_name test.local;\n")
		b.WriteString("        location / { return 200 \"$effective_ja4|$ja4_diag\"; }\n")
		b.WriteString("    }\n}\n")
		conf := filepath.Join(dir, "nginx.conf")
		if err := os.WriteFile(conf, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		s.Nginx.OutputDir = dir
		s.Nginx.ConfPath = conf
		if err := Render(s, dir, "test"); err != nil {
			t.Fatalf("Render: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, bin, "-p", dir, "-c", conf)
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatalf("nginx: %v", err)
		}
		t.Cleanup(func() {
			cancel()
			_ = cmd.Wait()
		})
		// Up when the plain port answers.
		deadline := time.Now().Add(10 * time.Second)
		for {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", plainPort), 200*time.Millisecond)
			if err == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				log, _ := os.ReadFile(filepath.Join(dir, "error.log"))
				t.Fatalf("nginx did not come up: %v\n%s", err, log)
			}
			time.Sleep(50 * time.Millisecond)
		}
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}, //nolint:gosec // a certificate made for this test
		}
		return func(tlsConn bool, header string) string {
			t.Helper()
			u := fmt.Sprintf("http://127.0.0.1:%d/", plainPort)
			if tlsConn {
				u = fmt.Sprintf("https://127.0.0.1:%d/", tlsPort)
			}
			req, err := http.NewRequest(http.MethodGet, u, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "test.local"
			if header != "" {
				req.Header.Set("X-Client-JA4", header)
			}
			resp, err := client.Do(req)
			if err != nil {
				log, _ := os.ReadFile(filepath.Join(dir, "error.log"))
				t.Fatalf("GET %s: %v\n%s", u, err, log)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return string(body)
		}
	}
	const forged = "t13d1516h2_8daaf6152771_02713d6af862"

	// The Google Cloud preset: its ranges are trusted, 127.0.0.1 is not.
	ask := start(t, "nginx:\n  trusted_lb_presets: [gcp]\n")

	own := ask(true, "")
	ja4, diag, _ := strings.Cut(own, "|")
	if ja4 == "" || ja4 == "NOT_TRUSTED" || diag != "ok" {
		t.Fatalf("a TLS connection with no header: %q, want the connection's own fingerprint and diag ok (is the module computing JA4?)", own)
	}
	if got := ask(true, forged); got != ja4+"|untrusted_lb_header" {
		t.Errorf("a TLS connection that sends a JA4 header from an untrusted address is judged by %q, want its own fingerprint %q (and the diagnosis)", got, ja4+"|untrusted_lb_header")
	}
	if got := ask(true, "anything at all"); got != ja4+"|untrusted_lb_header" {
		t.Errorf("...whatever the header holds: %q", got)
	}
	// Plain HTTP: no fingerprint of the connection's own.  The sentinel
	// still marks the header as untrusted, and nothing is judged by it.
	if got := ask(false, forged); got != "NOT_TRUSTED|untrusted_lb_header" {
		t.Errorf("a plain connection with an untrusted header: %q, want the sentinel", got)
	}
	if got := ask(false, ""); got != "|ok" {
		t.Errorf("a plain connection with no header: %q, want no fingerprint and diag ok", got)
	}

	// A trusted load balancer's header is the visitor's fingerprint, as ever.
	ask = start(t, "nginx:\n  trusted_lb_extra:\n    - id: local\n      cidrs: [\"127.0.0.1\"]\n      header: \"$http_x_client_ja4\"\n")
	if got := ask(true, forged); got != forged+"|ok" {
		t.Errorf("a trusted load balancer's header: %q, want %q", got, forged+"|ok")
	}
	if got := ask(false, forged); got != forged+"|ok" {
		t.Errorf("a trusted load balancer's header over plain HTTP: %q, want %q", got, forged+"|ok")
	}
}

// The same rule as the rendered text says it, for the runs with no nginx at
// hand: the untrusted header's row of the map names the connection's own
// fingerprint (or the sentinel, where it has none), never the sentinel alone.
func TestUntrustedHeaderMapNamesTheConnectionsFingerprint(t *testing.T) {
	var s settings.Settings
	s.Nginx.TrustedLBPresets = []string{"gcp"}
	http := renderHTTP(t, s)
	for _, want := range []string{
		"map $client_ja4 $unmask_untrusted_ja4 {",
		`"untrusted_lb_header" $unmask_untrusted_ja4;`,
	} {
		if !strings.Contains(http, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	if strings.Contains(http, `"untrusted_lb_header" "NOT_TRUSTED";`) {
		t.Error("an untrusted header still makes every such request NOT_TRUSTED")
	}
}

// freePort asks the kernel for a port nobody listens on.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// selfSigned writes a throwaway certificate and key for test.local into dir.
func selfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		DNSNames:     []string{"test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
