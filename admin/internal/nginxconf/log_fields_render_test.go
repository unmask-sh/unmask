package nginxconf

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The access-log line's fields that come from the request, ahead of the
// User-Agent, are logged through maps that admit no space: a space in the
// Host (nginx before 1.21.1 lets one through), in a JA4 header a trusted
// proxy passed on, or in the trap URL carried fields of the client's
// choosing into the line the daemon reads field by field.
func TestAccessLogFieldsCarryNoSpace(t *testing.T) {
	s := settings.Settings{}
	s.Nginx.ConfPath = filepath.Join(t.TempDir(), "nginx.conf")
	s.NginxLog.SocketPath = "/run/unmask/log.sock"
	out := renderHTTP(t, s)

	var format string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "log_format unmask_minimal ") {
			format = l
		}
	}
	if format == "" {
		t.Fatal("no log_format unmask_minimal in http.inc")
	}
	for _, want := range []string{" site=$unmask_site_log ", " ja4=$unmask_ja4_log ", " hpuri=$unmask_hp_uri_log "} {
		if !strings.Contains(format, want) {
			t.Errorf("log_format lacks %q:\n%s", want, format)
		}
	}
	for _, raw := range []string{"$host ", "$effective_ja4 ", "=$unmask_hp_uri "} {
		if strings.Contains(format, raw) {
			t.Errorf("log_format still logs %q as it is:\n%s", raw, format)
		}
	}

	// Each map's pattern, read back from http.inc, against what a client
	// could send.  The patterns are plain enough to mean the same to RE2 as
	// to nginx's PCRE.
	pattern := func(variable string) *regexp.Regexp {
		t.Helper()
		m := regexp.MustCompile(`(?s)map \S+ \` + variable + ` \{.*?"~(\^[^"]+)"`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("no map for %s in http.inc", variable)
		}
		return regexp.MustCompile(m[1])
	}
	site := pattern("$unmask_site_log")
	for _, ok := range []string{"shop.example.com", "[2001:db8::1]", "_", "xn--bcher-kva.example"} {
		if !site.MatchString(ok) {
			t.Errorf("$unmask_site_log refuses the Host %q", ok)
		}
	}
	for _, bad := range []string{"x kind= fc=0 hp=1 ip=203.0.113.9", "a\tb", strings.Repeat("a", 254)} {
		if site.MatchString(bad) {
			t.Errorf("$unmask_site_log logs the Host %q as it is", bad)
		}
	}
	ja4 := pattern("$unmask_ja4_log")
	if !ja4.MatchString("t13d1516h2_8daaf6152771_02713d6af862") || !ja4.MatchString("NOT_TRUSTED") {
		t.Errorf("$unmask_ja4_log refuses a fingerprint")
	}
	if ja4.MatchString("x hp=1 ip=203.0.113.9") {
		t.Errorf("$unmask_ja4_log logs a header with spaces as it is")
	}
	hp := pattern("$unmask_hp_uri_log")
	if got := hp.FindString("/wp-login.php?a=1 hp=1 ip=203.0.113.9"); got != "/wp-login.php?a=1" {
		t.Errorf("$unmask_hp_uri_log keeps %q of a URL with a space, want the part before it", got)
	}
	if got := hp.FindString("/" + strings.Repeat("A", 5000)); len(got) != 1000 {
		t.Errorf("$unmask_hp_uri_log keeps %d characters of a long URL, want 1000", len(got))
	}
}
