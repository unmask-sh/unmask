package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// fleetLikeDump is an `nginx -T` of a host behind Google's load balancer
// whose own server block lists the proxies' ranges, private ranges, a
// socket, and the whole 35.227.0.0/16 -- three quarters of it Google
// customers' machines -- for the load balancer's own address.
const fleetLikeDump = `# configuration file /etc/nginx/nginx.conf:
http {
    include /etc/nginx/conf.d/*.conf;
}

# configuration file /etc/nginx/conf.d/site.conf:
server {
  # set_real_ip_from 0.0.0.0/0;   (commented out: not loaded)
  set_real_ip_from 192.168.0.0/16;
  set_real_ip_from 127.0.0.1;
  set_real_ip_from ::1;
  set_real_ip_from unix:;
  set_real_ip_from 130.211.0.0/22;
  set_real_ip_from 35.191.0.0/16;
  set_real_ip_from 35.227.0.0/16;
  set_real_ip_from 2600:2d00:1:1::/64;     # GCP Global External ALB
  real_ip_header X-Forwarded-For;
  real_ip_recursive on;
}
`

func withRealIPDump(t *testing.T, dump string) {
	t.Helper()
	prev := nginxDumpRealIP
	nginxDumpRealIP = func(settings.Settings) string { return dump }
	t.Cleanup(func() { nginxDumpRealIP = prev })
}

// The files read directly come out in nginx -T's form, includes followed
// (glob, relative to nginx.conf's directory), so the check finds the line
// in the file it is in.
func TestNginxConfFilesDumpFollowsIncludes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("nginx.conf", "http {\n    include conf.d/*.conf;  # the sites\n}\n")
	write("conf.d/site.conf", "server {\n  include snippets/realip.inc;\n}\n")
	// nginx takes a relative include from its prefix, not from the file
	// that names it: conf.d/site.conf's "snippets/realip.inc" is <dir>/snippets.
	write("snippets/realip.inc", "set_real_ip_from 127.0.0.1;\nset_real_ip_from 35.227.0.0/16;\n")
	es := realIPFromEntries(nginxConfFilesDump(filepath.Join(dir, "nginx.conf")))
	if len(es) != 2 || es[1].value != "35.227.0.0/16" || es[1].line != 2 ||
		es[1].file != filepath.Join(dir, "snippets/realip.inc") {
		t.Fatalf("want 35.227.0.0/16 at snippets/realip.inc:2, got %+v", es)
	}
}

func TestRealIPFromEntriesFileAndLine(t *testing.T) {
	es := realIPFromEntries(fleetLikeDump)
	if len(es) != 8 {
		t.Fatalf("want the 8 loaded set_real_ip_from (the commented one is not), got %d: %+v", len(es), es)
	}
	wide := es[6]
	if wide.value != "35.227.0.0/16" || wide.file != "/etc/nginx/conf.d/site.conf" || wide.line != 9 {
		t.Fatalf("want 35.227.0.0/16 at /etc/nginx/conf.d/site.conf:9, got %+v", wide)
	}
	if es[3].pfx.IsValid() {
		t.Fatalf("unix: is no range, got %v", es[3].pfx)
	}
	if es[7].value != "2600:2d00:1:1::/64" {
		t.Fatalf("a trailing comment must not hide the value, got %q", es[7].value)
	}
	// Two directives on one line are two entries.
	two := realIPFromEntries("# configuration file /x.conf:\nset_real_ip_from 198.51.100.0/24; set_real_ip_from 203.0.113.7;\n")
	if len(two) != 2 || two[1].pfx.Bits() != 32 || two[1].line != 1 {
		t.Fatalf("want two entries on line 1, the second a /32, got %+v", two)
	}
}

func TestCheckRealIPFromNamesTheWideRange(t *testing.T) {
	withRealIPDump(t, fleetLikeDump)
	cap, addOK, addWarn, _ := newCaptures()
	checkRealIPFrom(settings.Settings{Nginx: settings.Nginx{TrustedLBPresets: []string{"gcp"}}}, addOK, addWarn)
	if len(cap.warn) != 1 || len(cap.ok) != 0 {
		t.Fatalf("want 1 WARN, got ok=%v warn=%v", cap.ok, cap.warn)
	}
	w := cap.warn[0]
	if !strings.Contains(w, "35.227.0.0/16 (/etc/nginx/conf.d/site.conf:9)") {
		t.Fatalf("the warning must name the range with its file and line: %s", w)
	}
	for _, fine := range []string{"35.191.0.0/16", "130.211.0.0/22", "192.168.0.0/16", "127.0.0.1", "2600:2d00:1:1::/64"} {
		if strings.Contains(w, fine+" (") {
			t.Fatalf("%s is the load balancer's or the host's own and must not be named: %s", fine, w)
		}
	}
}

func TestCheckRealIPFromNarrowedIsOK(t *testing.T) {
	withRealIPDump(t, strings.Replace(fleetLikeDump, "35.227.0.0/16", "35.227.192.0/18", 1))
	cap, addOK, addWarn, _ := newCaptures()
	checkRealIPFrom(settings.Settings{Nginx: settings.Nginx{TrustedLBPresets: []string{"gcp"}}}, addOK, addWarn)
	if len(cap.ok) != 1 || len(cap.warn) != 0 {
		t.Fatalf("the load balancers' own range is trusted by the preset: want 1 OK, got ok=%v warn=%v", cap.ok, cap.warn)
	}
}

func TestCheckRealIPFromNamesThePresetThatIsOff(t *testing.T) {
	withRealIPDump(t, "# configuration file /etc/nginx/conf.d/a.conf:\nset_real_ip_from 130.211.0.0/22;\n")
	cap, addOK, addWarn, _ := newCaptures()
	checkRealIPFrom(settings.Settings{}, addOK, addWarn)
	if len(cap.warn) != 1 || !strings.Contains(cap.warn[0], "GCP HTTPS Load Balancer") || !strings.Contains(cap.warn[0], "which is off") {
		t.Fatalf("want a WARN that names the gcp preset as off, got ok=%v warn=%v", cap.ok, cap.warn)
	}
}

func TestCheckRealIPFromCustomLBAndEverything(t *testing.T) {
	n := settings.Nginx{TrustedLBExtra: []settings.TrustedLBExtra{{ID: "own-lb", CIDRs: []string{"203.0.113.0/24"}}}}
	withRealIPDump(t, "# configuration file /e.conf:\nset_real_ip_from 203.0.113.64/26;\n")
	cap, addOK, addWarn, _ := newCaptures()
	checkRealIPFrom(settings.Settings{Nginx: n}, addOK, addWarn)
	if len(cap.ok) != 1 || len(cap.warn) != 0 {
		t.Fatalf("a range inside a custom trusted LB is fine: got ok=%v warn=%v", cap.ok, cap.warn)
	}
	withRealIPDump(t, "# configuration file /e.conf:\nset_real_ip_from 0.0.0.0/0;\nset_real_ip_from 203.0.113.0/23;\n")
	cap, addOK, addWarn, _ = newCaptures()
	checkRealIPFrom(settings.Settings{Nginx: n}, addOK, addWarn)
	if len(cap.warn) != 1 || !strings.Contains(cap.warn[0], "0.0.0.0/0 (") || !strings.Contains(cap.warn[0], "203.0.113.0/23 (") {
		t.Fatalf("everything, and a range wider than the custom LB, are named: got ok=%v warn=%v", cap.ok, cap.warn)
	}
}

func TestCheckRealIPFromSilentWithoutDump(t *testing.T) {
	withRealIPDump(t, "")
	cap, addOK, addWarn, _ := newCaptures()
	checkRealIPFrom(settings.Settings{}, addOK, addWarn)
	if len(cap.ok)+len(cap.warn) != 0 {
		t.Fatalf("no nginx -T, no line: got ok=%v warn=%v", cap.ok, cap.warn)
	}
}
