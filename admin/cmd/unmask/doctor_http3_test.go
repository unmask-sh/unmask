package main

import (
	"strings"
	"testing"
)

// The HTTP/3 verdict: a build with an OpenSSL before 3.5.1 (and not quictls)
// serving a `listen ... quic` socket gets no JA4 on those connections.
func TestHTTP3JA4Verdict(t *testing.T) {
	v := func(ssl string, v3 bool) string {
		s := "nginx version: nginx/1.28.0\nbuilt by gcc 13.2.0\nbuilt with " + ssl + "\nTLS SNI support enabled\nconfigure arguments: --prefix=/etc/nginx --with-http_ssl_module --with-http_v2_module"
		if v3 {
			s += " --with-http_v3_module"
		}
		return s + " --with-compat\n"
	}
	const quicConf = "# configuration file /etc/nginx/conf.d/site.conf:\nserver {\n    listen 443 ssl;\n    listen 443 quic reuseport;\n    listen [::]:443 quic;\n    http2 on;\n}\n"
	const plainConf = "server {\n    listen 443 ssl;\n    # listen 443 quic;\n}\n"
	cases := []struct {
		name    string
		v, dump string
		warn    bool
		mention []string
	}{
		{"openssl 3.2 serving quic", v("OpenSSL 3.2.2 4 Jun 2024 (running with OpenSSL 3.2.2 4 Jun 2024)", true), quicConf, true, []string{"3.2.2", "2 `listen ... quic` socket(s): 443, [::]:443", "OpenSSL 3.5.1 or newer, or with quictls"}},
		{"openssl 3.5.0 serving quic", v("OpenSSL 3.5.0 8 Apr 2025", true), quicConf, true, []string{"3.5.0"}},
		{"openssl 1.1.1 serving quic", v("OpenSSL 1.1.1w  11 Sep 2023", true), quicConf, true, []string{"1.1.1w"}},
		{"openssl 3.5.1: has the QUIC API", v("OpenSSL 3.5.1 1 Jul 2025", true), quicConf, false, nil},
		{"openssl 3.6: has the QUIC API", v("OpenSSL 3.6.5 29 Sep 2026", true), quicConf, false, nil},
		{"quictls", v("OpenSSL 3.0.13+quic 30 Jan 2024", true), quicConf, false, nil},
		{"boringssl", v("BoringSSL", true), quicConf, false, nil},
		{"libressl", v("LibreSSL 3.9.2", true), quicConf, false, nil},
		{"no quic listen (a commented one does not count)", v("OpenSSL 3.2.2 4 Jun 2024", true), plainConf, false, nil},
		{"no http_v3_module", v("OpenSSL 3.2.2 4 Jun 2024", false), quicConf, false, nil},
		{"configuration not readable (nginx -T needs root)", v("OpenSSL 3.2.2 4 Jun 2024", true), "", false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			warn, msg := http3JA4Verdict(c.v, c.dump)
			if warn != c.warn {
				t.Fatalf("warn=%v, want %v (%s)", warn, c.warn, msg)
			}
			for _, m := range c.mention {
				if !strings.Contains(msg, m) {
					t.Errorf("the warning does not mention %q: %s", m, msg)
				}
			}
		})
	}
}
