package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cdn"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// directives counts the lines that are the directive -- not a comment that
// names it (http.conf.tmpl explains real_ip in its comments).
func directives(conf, name string) int {
	n := 0
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), name+" ") {
			n++
		}
	}
	return n
}

func renderHTTP(t *testing.T, s settings.Settings) string {
	t.Helper()
	dir := t.TempDir()
	s.Nginx.OutputDir = dir
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The CloudFront preset takes its ranges from the cdn table (the snapshot
// built into the binary here), names the empty JA4 variable http.inc
// declares, and -- with the real_ip switch -- http.inc carries
// set_real_ip_from for every range, X-Forwarded-For and recursive; without
// the switch, none of the real_ip block.
func TestCloudFrontPresetAndRealIP(t *testing.T) {
	cdn.Set(nil)
	s := settings.Settings{}
	s.Nginx.ConfPath = filepath.Join(t.TempDir(), "nginx.conf") // absent: nothing declared by the host
	s.Nginx.TrustedLBPresets = []string{"cloudfront"}

	lbs := EffectiveLBs(s.Nginx)
	if len(lbs) != 1 || lbs[0].ID != "cloudfront" || lbs[0].Header != NoJA4HeaderVar {
		t.Fatalf("effective set: %+v", lbs)
	}
	want := cdn.Snapshot().Ranges("cloudfront")
	if len(want) == 0 || len(lbs[0].CIDRs) != len(want) {
		t.Fatalf("the preset carries %d ranges, the snapshot %d", len(lbs[0].CIDRs), len(want))
	}

	off := renderHTTP(t, s)
	if !strings.Contains(off, "map $host $unmask_lb_no_ja4") || !strings.Contains(off, `"cloudfront" $unmask_lb_no_ja4;`) {
		t.Error("the empty JA4 variable, or the preset's use of it, is missing")
	}
	if directives(off, "real_ip_header") != 0 || directives(off, "set_real_ip_from") != 0 {
		t.Error("the real_ip block is rendered although the switch is off")
	}
	if !strings.Contains(off, want[0]+` "cloudfront";`) {
		t.Errorf("the vendor geo lacks the first CloudFront range %s", want[0])
	}

	s.Nginx.TrustedLBRealIP = true
	on := renderHTTP(t, s)
	for _, w := range []string{"set_real_ip_from " + want[0] + ";", "set_real_ip_from " + want[len(want)-1] + ";",
		"real_ip_header X-Forwarded-For;", "real_ip_recursive on;"} {
		if !strings.Contains(on, w) {
			t.Errorf("the real_ip block lacks %q", w)
		}
	}
	if n := directives(on, "set_real_ip_from"); n != len(want) {
		t.Errorf("%d set_real_ip_from lines, want %d", n, len(want))
	}
	if directives(on, "real_ip_header") != 1 || directives(on, "real_ip_recursive") != 1 {
		t.Error("real_ip_header / real_ip_recursive must appear once each")
	}

	// The host already sets real_ip_header: ours stays out.
	if err := os.WriteFile(s.Nginx.ConfPath, []byte("http {\n  real_ip_header X-Real-IP; # theirs\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !HostDeclaresRealIPHeader(s) {
		t.Fatal("the host's real_ip_header was not seen")
	}
	host := renderHTTP(t, s)
	if directives(host, "real_ip_header") != 0 || directives(host, "set_real_ip_from") != 0 {
		t.Error("the real_ip block is rendered over the host's own real_ip_header")
	}
	// A commented-out one does not count.
	if err := os.WriteFile(s.Nginx.ConfPath, []byte("http {\n  # real_ip_header X-Real-IP;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if HostDeclaresRealIPHeader(s) {
		t.Error("a commented real_ip_header counted as declared")
	}
}
