package nginxconf

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func gcpPreset(t *testing.T) LBIPRange {
	t.Helper()
	for _, p := range LBIPRanges {
		if p.ID == "gcp" {
			return p
		}
	}
	t.Fatal("no gcp preset")
	return LBIPRange{}
}

// The Google Cloud preset trusted 35.227.0.0/16 as if the load balancer's
// proxies connected from it.  Three quarters of that range are customers'
// machines (us-east1, us-west1): one of them was a trusted proxy to an origin
// it could reach, and was read past like a proxy when it came through the
// load balancer.  What the range was listed for is its last quarter,
// 35.227.192.0/18, where load balancers' own addresses are -- needed for one
// thing only: Google ends X-Forwarded-For with the load balancer's address,
// and real_ip has to read past it.
//
// So the preset has two lists.  CIDRs: where the proxies connect from,
// trusted to forward the visitor's JA4 and address.  XFFHops: that last
// quarter, read past in X-Forwarded-For and trusted for nothing else -- and
// nothing beyond it, since every range read past is one a client could be
// read past in too.
func TestGCPPresetTrustsTheProxiesAndReadsPastTheLBAddresses(t *testing.T) {
	gcp := gcpPreset(t)
	customers := []netip.Prefix{netip.MustParsePrefix("35.227.0.0/17"), netip.MustParsePrefix("35.227.128.0/18")}
	for _, list := range [][]string{gcp.CIDRs, gcp.XFFHops} {
		for _, c := range list {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				t.Errorf("%q is not a prefix: %v", c, err)
				continue
			}
			for _, cust := range customers {
				if p.Overlaps(cust) {
					t.Errorf("the preset lists %s, which overlaps %s -- a range Google assigns to customers' machines", c, cust)
				}
			}
		}
	}
	// The two lists do not overlap: an address is a proxy's or a frontend's.
	for _, c := range gcp.CIDRs {
		for _, h := range gcp.XFFHops {
			if netip.MustParsePrefix(c).Overlaps(netip.MustParsePrefix(h)) {
				t.Errorf("%s is both a proxy range and a frontend range (%s)", c, h)
			}
		}
	}
	// The read-past list is the /16's last quarter and nothing more.
	if len(gcp.XFFHops) != 1 || gcp.XFFHops[0] != "35.227.192.0/18" {
		t.Errorf("the read-past list is %v, want just 35.227.192.0/18 (what the /16 covered of load balancers' addresses)", gcp.XFFHops)
	}
	hop := func(ip string) bool {
		a := netip.MustParseAddr(ip)
		for _, h := range gcp.XFFHops {
			if netip.MustParsePrefix(h).Contains(a) {
				return true
			}
		}
		return false
	}
	if !hop("35.227.200.20") {
		t.Error("35.227.200.20, a global load balancer's own address, is not read past")
	}
	// A load balancer address anywhere else is the operator's to list: the
	// preset reads past nothing it did not before.
	for _, ip := range []string{"34.120.1.1", "2600:1901:0:1234::", "35.227.10.10"} {
		if hop(ip) {
			t.Errorf("%s is read past by the preset", ip)
		}
	}

	n := settings.Nginx{TrustedLBPresets: []string{"gcp"}}
	for _, ip := range []string{"35.191.7.7", "130.211.1.1"} {
		if ok, _ := IsTrustedLBIP(ip, n); !ok {
			t.Errorf("%s, one of the load balancer's proxies, is not trusted", ip)
		}
	}
	// Neither a customer's machine nor a frontend address is a proxy: a
	// request from one names nobody's JA4.
	for _, ip := range []string{"35.227.10.10", "35.227.130.9", "35.227.200.20"} {
		if ok, _ := IsTrustedLBIP(ip, n); ok {
			t.Errorf("%s is taken for one of the load balancer's proxies", ip)
		}
	}
	for _, c := range EffectiveLBCIDRs(n) {
		if strings.HasPrefix(c, "35.227.") {
			t.Errorf("the peer list carries %s", c)
		}
	}
}

// In the rendered files: the real_ip block lists the proxies and the
// frontends, the geo that decides whose JA4 header is believed lists the
// proxies alone, and an install that had nothing but the preset renders as
// before -- no entry of the operator's own is asked for.
func TestGCPRenderReadsPastTheLBAddressesOnly(t *testing.T) {
	// The host's nginx.conf, with no real_ip_header of its own: unmask writes
	// the block.  (Left unset, the path is this machine's /etc/nginx.)
	bare := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(bare, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir, _, err := renderAfterAPlainOne(t, func(s *settings.Settings) {
		s.Nginx.TrustedLBPresets = []string{"gcp"}
		s.Nginx.TrustedLBRealIP = true
		s.Nginx.ConfPath = bare
	})
	if err != nil {
		t.Fatalf("the preset alone does not render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	http := string(b)
	for _, want := range []string{
		"set_real_ip_from 35.191.0.0/16;", "set_real_ip_from 130.211.0.0/22;",
		"set_real_ip_from 35.227.192.0/18;",
		"real_ip_header X-Forwarded-For;", "real_ip_recursive on;",
	} {
		if !strings.Contains(http, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
	for _, bad := range []string{"35.227.0.0/16", "35.227.0.0/17", "35.227.128.0/18"} {
		if strings.Contains(http, bad) {
			t.Errorf("http.inc names %s, customers' machines", bad)
		}
	}
	// The geo: the proxies are there under the vendor's name, a frontend
	// range is not.
	geo := http[strings.Index(http, "geo $realip_remote_addr $unmask_lb_vendor {"):]
	geo = geo[:strings.Index(geo, "\n}")]
	if !strings.Contains(geo, `35.191.0.0/16 "gcp";`) {
		t.Errorf("the geo lost the proxies:\n%s", geo)
	}
	if strings.Contains(geo, "35.227.") {
		t.Errorf("the geo trusts a frontend range to name a JA4:\n%s", geo)
	}

	// Without the real_ip block the frontends are named nowhere.
	dir, _, err = renderAfterAPlainOne(t, func(s *settings.Settings) {
		s.Nginx.TrustedLBPresets = []string{"gcp"}
		s.Nginx.ConfPath = bare
	})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "http.inc")); strings.Contains(string(b), "35.227.192.0/18") {
		t.Error("with trusted_lb_realip off, http.inc still names the frontend ranges")
	}

	// The gateway writes its real_ip block from the same set.
	dir, _, err = renderAfterAPlainOne(t, func(s *settings.Settings) {
		s.Gateway = settings.GatewayConfig{Certificates: []settings.GatewayCertificate{{CertPath: "/c.pem", KeyPath: "/k.pem"}}}
		s.Nginx.TrustedLBPresets = []string{"gcp"}
		s.Nginx.ConfPath = bare
	})
	if err != nil {
		t.Fatalf("the gateway with the preset alone does not render: %v", err)
	}
	prx, err := os.ReadFile(filepath.Join(dir, "gateway-proxies.inc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"set_real_ip_from 35.191.0.0/16;", "set_real_ip_from 35.227.192.0/18;"} {
		if !strings.Contains(string(prx), want) {
			t.Errorf("gateway-proxies.inc lacks %q", want)
		}
	}
	if strings.Contains(string(prx), "35.227.0.0/1") {
		t.Errorf("gateway-proxies.inc names customers' machines:\n%s", prx)
	}
}
