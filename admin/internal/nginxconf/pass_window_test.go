package nginxconf

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// passWindowYAML: a default of two hours for both kinds of pass, a site that
// keeps them one hour and a site that keeps them a day.
const passWindowYAML = `challenge:
  default:
    pow_cookie_valid_seconds: 7200
    captcha_cookie_valid_seconds: 7200
  sites:
    short.test.local:
      pow_cookie_valid_seconds: 3600
      captcha_cookie_valid_seconds: 3600
    long.test.local:
      pow_cookie_valid_seconds: 86400
      captcha_cookie_valid_seconds: 86400
    same.test.local:
      pow_cookie_valid_seconds: 7200
    off.test.local:
      disabled: true
      pow_cookie_valid_seconds: 60
`

// A site's own pass windows reach nginx: http.inc carries the default in the
// two directives and, beside them, a map per kind keyed on the host, with a
// row for each site whose window differs.  The render wrote the default's
// alone, so the module let a pass through for the default's days on a site
// set to an hour, where the daemon had stopped honouring it.
func TestPerSitePassWindowsAreRendered(t *testing.T) {
	s, err := settings.LoadFromYAML("secret:\n  bv_secret: \"0123456789abcdef0123456789abcdef\"\n" + passWindowYAML)
	if err != nil {
		t.Fatal(err)
	}
	http := renderHTTP(t, s)
	block := func(name string) string {
		t.Helper()
		i := strings.Index(http, "map $host "+name+" {")
		if i < 0 {
			t.Fatalf("http.inc has no map for %s", name)
		}
		return http[i : i+strings.Index(http[i:], "}")]
	}
	for _, name := range []string{"$unmask_pow_valid_seconds", "$unmask_captcha_valid_seconds"} {
		m := block(name)
		for _, want := range []string{"default 7200;", `"short.test.local" 3600;`, `"long.test.local" 86400;`} {
			if !strings.Contains(m, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, m)
			}
		}
		// A site on the default's window needs no row, and a switched-off
		// site's values are nobody's.
		for _, not := range []string{"same.test.local", "off.test.local"} {
			if strings.Contains(m, not) {
				t.Errorf("%s names %s:\n%s", name, not, m)
			}
		}
	}
	for _, want := range []string{"unmask_bv_pow_valid_seconds     7200;", "unmask_bv_captcha_valid_seconds 7200;"} {
		if !strings.Contains(http, want) {
			t.Errorf("http.inc lacks the default's directive %q", want)
		}
	}
}

// TestNginxHoldsAPassToItsSitesWindow runs a real nginx with the module and
// presents it passes of three ages on three hosts: the default's (two
// hours), a site that keeps a pass one hour and a site that keeps one a day.
// nginx has to say what the daemon says of each -- the daemon reads the
// site's window (Challenge.Resolve), and the module read the directive's,
// the default, on every host: ninety minutes old on the one-hour site it let
// a pass through that the daemon no longer honoured, and three hours old on
// the one-day site it refused a pass the daemon still counted good.
//
// Skipped unless UNMASK_TEST_NGINX and UNMASK_TEST_NGINX_MODULE are set:
// `make test-nginx-accepts` sets both.
func TestNginxHoldsAPassToItsSitesWindow(t *testing.T) {
	bin, mod := os.Getenv("UNMASK_TEST_NGINX"), os.Getenv("UNMASK_TEST_NGINX_MODULE")
	if bin == "" || mod == "" {
		t.Skip("UNMASK_TEST_NGINX / UNMASK_TEST_NGINX_MODULE are not set")
	}
	// startNginx's secret and its address.
	const secret, addr = "0123456789abcdef0123456789abcdef", "127.0.0.1"
	s, err := settings.LoadFromYAML(passWindowYAML)
	if err != nil {
		t.Fatal(err)
	}
	ask := startNginx(t, bin, mod, passWindowYAML, "$unmask_bv_kind")
	now := time.Now().Unix()
	for _, c := range []struct {
		host string
		age  int64 // seconds since the pass was issued
		good bool
	}{
		{"test.local", 600, true},
		{"test.local", 5400, true},
		{"test.local", 10800, false},
		{"short.test.local", 600, true},
		{"short.test.local", 5400, false},
		{"long.test.local", 5400, true},
		{"long.test.local", 10800, true},
		{"long.test.local", 90000, false},
	} {
		ch := s.Challenge.Resolve(c.host)
		for _, p := range []struct{ kind, value string }{
			{"pow", mintPowPass(t, secret, addr, c.host, now-c.age)},
			{"captcha", cookies.IssueValueAt(secret, addr, c.host, "captcha", now-c.age)},
		} {
			daemon := cookies.Verify(p.value, secret, addr, c.host,
				ch.PowCookieValidSecondsResolved(), ch.CaptchaCookieValidSecondsResolved(), 8)
			if daemon != c.good {
				t.Fatalf("%s pass aged %ds on %s: the daemon says %v, the table %v", p.kind, c.age, c.host, daemon, c.good)
			}
			want := ""
			if c.good {
				want = p.kind
			}
			if got := ask(false, map[string]string{"Host": c.host, "Cookie": "_bv=" + p.value}); got != want {
				t.Errorf("%s pass aged %ds on %s: nginx says %q, the daemon %q", p.kind, c.age, c.host, got, want)
			}
		}
	}
}
