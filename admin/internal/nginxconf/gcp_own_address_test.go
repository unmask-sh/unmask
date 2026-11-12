package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The Google Cloud preset is the load balancer's proxies and health checks:
// ranges Google keeps for itself.  35.227.0.0/16 was among them, and Google
// assigns that one to customers -- a machine there, reaching the origin
// directly, was trusted to name its own JA4 and, with the real_ip block, its
// own address.
func TestGCPPresetNamesNoCustomerRange(t *testing.T) {
	var gcp *LBIPRange
	for i := range LBIPRanges {
		if LBIPRanges[i].ID == "gcp" {
			gcp = &LBIPRanges[i]
		}
	}
	if gcp == nil {
		t.Fatal("no gcp preset")
	}
	for _, c := range gcp.CIDRs {
		if strings.HasPrefix(c, "35.227.") {
			t.Errorf("the gcp preset trusts %s, a range Google assigns to customers", c)
		}
	}
	n := settings.Nginx{TrustedLBPresets: []string{"gcp"}}
	if ok, _ := IsTrustedLBIP("35.227.10.10", n); ok {
		t.Error("an address of 35.227.0.0/16 is taken for the load balancer")
	}
	for _, ip := range []string{"35.191.7.7", "130.211.1.1"} {
		if ok, _ := IsTrustedLBIP(ip, n); !ok {
			t.Errorf("%s, one of the load balancer's proxies, is not trusted", ip)
		}
	}
}

// Behind a Google load balancer X-Forwarded-For ends with the load balancer's
// own address.  With the real_ip block on and that address not trusted, nginx
// would name it as every visitor's.  The /16 the preset used to carry covered
// the address for a load balancer that lies in it; without the /16 the
// operator lists the address, and a render that would turn all visitors into
// one is refused instead of written -- the files of the last render, which
// still read past the address, stay until it is listed.
func TestRenderAsksForTheLoadBalancersOwnAddress(t *testing.T) {
	own := settings.TrustedLBExtra{ID: "my-lb", CIDRs: []string{"203.0.113.9", "2001:db8:9::1"}}
	// The host's nginx.conf, with no real_ip_header of its own: unmask writes
	// the block.  (Left unset, the path is this machine's /etc/nginx.)
	bare := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(bare, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("no address of one's own: refused", func(t *testing.T) {
		dir, before, err := renderAfterAPlainOne(t, func(s *settings.Settings) {
			s.Nginx.TrustedLBPresets = []string{"gcp"}
			s.Nginx.TrustedLBRealIP = true
			s.Nginx.ConfPath = bare
		})
		if err == nil {
			t.Fatal("the render went through")
		}
		for _, want := range []string{"render refused", "trusted_lb_extra", "X-Forwarded-For", "trusted_lb_realip"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error does not mention %q: %v", want, err)
			}
		}
		after := readDir(t, dir)
		for name, body := range before {
			if after[name] != body {
				t.Errorf("the refused render rewrote %s", name)
			}
		}
	})

	t.Run("an entry that is switched off does not count", func(t *testing.T) {
		off := own
		off.Disabled = true
		if _, _, err := renderAfterAPlainOne(t, func(s *settings.Settings) {
			s.Nginx.TrustedLBPresets = []string{"gcp"}
			s.Nginx.TrustedLBRealIP = true
			s.Nginx.ConfPath = bare
			s.Nginx.TrustedLBExtra = []settings.TrustedLBExtra{off}
		}); err == nil {
			t.Fatal("the render went through with the only entry switched off")
		}
	})

	t.Run("with the address listed: rendered, and the /16 is gone", func(t *testing.T) {
		dir, _, err := renderAfterAPlainOne(t, func(s *settings.Settings) {
			s.Nginx.TrustedLBPresets = []string{"gcp"}
			s.Nginx.TrustedLBRealIP = true
			s.Nginx.ConfPath = bare
			s.Nginx.TrustedLBExtra = []settings.TrustedLBExtra{own}
		})
		if err != nil {
			t.Fatalf("refused with the address listed: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "http.inc"))
		if err != nil {
			t.Fatal(err)
		}
		http := string(b)
		for _, want := range []string{"set_real_ip_from 35.191.0.0/16;", "set_real_ip_from 130.211.0.0/22;", "set_real_ip_from 203.0.113.9;", "set_real_ip_from 2001:db8:9::1;", "real_ip_recursive on;"} {
			if !strings.Contains(http, want) {
				t.Errorf("http.inc lacks %q", want)
			}
		}
		if strings.Contains(http, "35.227.") {
			t.Error("http.inc still names 35.227.0.0/16")
		}
	})

	t.Run("without the real_ip block there is nothing to ask", func(t *testing.T) {
		if _, _, err := renderAfterAPlainOne(t, func(s *settings.Settings) {
			s.Nginx.TrustedLBPresets = []string{"gcp"}
			s.Nginx.ConfPath = bare
		}); err != nil {
			t.Fatalf("refused with trusted_lb_realip off: %v", err)
		}
	})

	t.Run("nor where the host's nginx.conf restores the address itself", func(t *testing.T) {
		conf := filepath.Join(t.TempDir(), "nginx.conf")
		if err := os.WriteFile(conf, []byte("http {\n    set_real_ip_from 35.191.0.0/16;\n    real_ip_header X-Forwarded-For;\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := renderAfterAPlainOne(t, func(s *settings.Settings) {
			s.Nginx.TrustedLBPresets = []string{"gcp"}
			s.Nginx.TrustedLBRealIP = true
			s.Nginx.ConfPath = conf
		}); err != nil {
			t.Fatalf("refused although unmask writes no real_ip block there: %v", err)
		}
	})

	// The gateway writes its real_ip block from the same set whenever the set
	// is not empty, trusted_lb_realip or not: it is asked the same.
	gateway := settings.GatewayConfig{Certificates: []settings.GatewayCertificate{{CertPath: "/c.pem", KeyPath: "/k.pem"}}}
	t.Run("the gateway, with no address of one's own: refused", func(t *testing.T) {
		if _, _, err := renderAfterAPlainOne(t, func(s *settings.Settings) {
			s.Gateway = gateway
			s.Nginx.TrustedLBPresets = []string{"gcp"}
			s.Nginx.ConfPath = bare
		}); err == nil || !strings.Contains(err.Error(), "gateway") {
			t.Fatalf("the gateway's render went through, or the error does not name the gateway: %v", err)
		}
	})
	t.Run("the gateway, with the address listed: rendered", func(t *testing.T) {
		dir, _, err := renderAfterAPlainOne(t, func(s *settings.Settings) {
			s.Gateway = gateway
			s.Nginx.TrustedLBPresets = []string{"gcp"}
			s.Nginx.ConfPath = bare
			s.Nginx.TrustedLBExtra = []settings.TrustedLBExtra{own}
		})
		if err != nil {
			t.Fatalf("refused with the address listed: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "gateway-proxies.inc"))
		if err != nil {
			t.Fatal(err)
		}
		if prx := string(b); !strings.Contains(prx, "set_real_ip_from 203.0.113.9;") || strings.Contains(prx, "35.227.") {
			t.Errorf("gateway-proxies.inc:\n%s", prx)
		}
	})

	t.Run("another vendor's preset is not asked", func(t *testing.T) {
		if _, _, err := renderAfterAPlainOne(t, func(s *settings.Settings) {
			s.Nginx.TrustedLBPresets = []string{"cloudflare"}
			s.Nginx.TrustedLBRealIP = true
			s.Nginx.ConfPath = bare
		}); err != nil {
			t.Fatalf("a Cloudflare install was refused: %v", err)
		}
	})
}
