package nginxpath

import (
	"os"
	"path/filepath"
	"testing"
)

// The configuration file is read out of `nginx -V` the way the package
// scripts read it (rpm/scripts, the nginx-layout block): the two must agree
// on whose nginx a host runs, or the scripts leave alone a file the daemon
// then does not read.
func TestFromVersionOutput(t *testing.T) {
	for _, tc := range []struct {
		name, out, want string
	}{
		{"nginx.org's package",
			"nginx version: nginx/1.26.3\nbuilt with OpenSSL 3.0.13 30 Jan 2024\nconfigure arguments: --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --with-compat",
			Packaged},
		{"Debian's package, quoted options with spaces ahead of the path",
			"nginx version: nginx/1.22.1\nconfigure arguments: --with-cc-opt='-g -O2 -ffile-prefix-map=/build/nginx-AoTv4W/nginx-1.22.1=. -fstack-protector-strong' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --modules-path=/usr/lib/nginx/modules --with-compat",
			Packaged},
		{"a hosting panel's build: conf/nginx.conf under its prefix",
			"nginx version: nginx/1.26.3\nbuilt with OpenSSL 1.1.1w  11 Sep 2023\nconfigure arguments: --user=www --group=www --prefix=/www/server/nginx --with-openssl=/www/server/nginx/src/openssl --with-http_ssl_module --with-ld-opt=-Wl,-E --with-compat",
			"/www/server/nginx/conf/nginx.conf"},
		{"no prefix at all: nginx's own default",
			"nginx version: nginx/1.28.3\nconfigure arguments: --with-compat --with-http_ssl_module",
			"/usr/local/nginx/conf/nginx.conf"},
		{"a relative --conf-path is under the prefix",
			"nginx version: nginx/1.28.3\nconfigure arguments: --prefix=/opt/nginx --conf-path=etc/nginx.conf --with-compat",
			"/opt/nginx/etc/nginx.conf"},
		{"built from source onto the distributions' path",
			"nginx version: nginx/1.28.3\nconfigure arguments: --prefix=/opt/nginx --conf-path=/etc/nginx/nginx.conf",
			Packaged},
		{"an empty configure line", "nginx version: nginx/1.28.3\nconfigure arguments:", "/usr/local/nginx/conf/nginx.conf"},
		{"nothing printed", "", Packaged},
		{"not an nginx", "sh: nginx: Permission denied", Packaged},
	} {
		if got := FromVersionOutput(tc.out); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestConfPath(t *testing.T) {
	old := versionOutput
	t.Cleanup(func() { versionOutput = old; resetProbe() })

	asked := 0
	versionOutput = func() (string, bool) {
		asked++
		return "configure arguments: --prefix=/www/server/nginx --with-compat", true
	}
	resetProbe()

	// What the operator configured is taken as it is, and nginx is not asked.
	if got := ConfPath("  /srv/nginx/nginx.conf "); got != "/srv/nginx/nginx.conf" || asked != 0 {
		t.Errorf("configured path: %q, asked %d", got, asked)
	}
	if SelfBuilt(Packaged) {
		t.Error("a configured distribution path reads as a self-built nginx")
	}

	// Otherwise the nginx on PATH says, and its answer is kept for a while.
	if got := ConfPath(""); got != "/www/server/nginx/conf/nginx.conf" {
		t.Errorf("probed path: %q", got)
	}
	if !SelfBuilt("") {
		t.Error("a panel's nginx does not read as a self-built one")
	}
	if asked != 1 {
		t.Errorf("nginx -V was run %d times for two questions inside the cache's lifetime", asked)
	}

	// No nginx to ask: the distributions' path, as before there was a probe.
	versionOutput = func() (string, bool) { return "", false }
	resetProbe()
	if got := ConfPath(""); got != Packaged || SelfBuilt("") {
		t.Errorf("no nginx: %q", got)
	}
}

// The two include lines an operator adds to a self-built nginx's
// configuration, found wherever nginx would find them.
func TestMissingOwnIncludes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	conf := filepath.Join(dir, "conf", "nginx.conf")
	check := func(name string, wantMain, wantHTTP bool) {
		t.Helper()
		m, h, ok, _ := MissingOwnIncludes(conf)
		if !ok || m != wantMain || h != wantHTTP {
			t.Errorf("%s: missing main=%v http=%v readable=%v, want main=%v http=%v", name, m, h, ok, wantMain, wantHTTP)
		}
	}

	if _, _, ok, _ := MissingOwnIncludes(conf); ok {
		t.Error("a configuration that is not there reads as readable")
	}

	write("conf/nginx.conf", "user www www;\nevents { }\nhttp {\n    include mime.types;\n    include "+dir+"/vhost/*.conf;\n}\n")
	write("conf/mime.types", "types { }\n")
	write("vhost/site.conf", "server { listen 80; }\n")
	check("neither line", true, true)

	write("conf/nginx.conf", "include "+OwnMainDir+"/*.conf;\nuser www www;\nevents { }\nhttp {\n    include "+dir+"/vhost/*.conf;\n}\n")
	check("the module line only", false, true)

	// The http line in a file of the vhost directory: inside http {} all the same.
	write("vhost/0.unmask.conf", "include "+OwnHTTPDir+"/*.conf;\n")
	check("both, one in an included file", false, false)

	// Quoted, spaced otherwise, after a brace on the same line.
	write("conf/nginx.conf", "  include   \""+OwnMainDir+"/*.conf\" ;\nhttp { include '"+OwnHTTPDir+"/*.conf'; }\n")
	os.Remove(filepath.Join(dir, "vhost", "0.unmask.conf"))
	check("quoted and spaced otherwise", false, false)

	// Commented out, or another file of the directory, is not the line.
	write("conf/nginx.conf", "# include "+OwnMainDir+"/*.conf;\nhttp {\n    #include "+OwnHTTPDir+"/*.conf;\n    include "+OwnHTTPDir+"/other.conf;\n}\n")
	check("commented out, or another file", true, true)

	// A relative include is read against the configuration's directory, and
	// one that leads back to its includer ends.
	write("conf/nginx.conf", "include extra/main.conf;\nhttp { include extra/loop.conf; }\n")
	write("conf/extra/main.conf", "include "+OwnMainDir+"/*.conf;\n")
	write("conf/extra/loop.conf", "include extra/loop.conf;\ninclude "+OwnHTTPDir+"/*.conf;\n")
	check("relative includes, and a loop", false, false)

	// An included file the reader may not open is named: the line may be in it.
	if os.Getuid() != 0 {
		write("conf/nginx.conf", "include "+OwnMainDir+"/*.conf;\nhttp { include "+dir+"/vhost/*.conf; }\n")
		closed := write("vhost/closed.conf", "include "+OwnHTTPDir+"/*.conf;\n")
		if err := os.Chmod(closed, 0o000); err != nil {
			t.Fatal(err)
		}
		m, h, ok, unread := MissingOwnIncludes(conf)
		if !ok || m || !h || len(unread) != 1 || unread[0] != closed {
			t.Errorf("an unreadable include: main=%v http=%v readable=%v unread=%v", m, h, ok, unread)
		}
	}
}

// The placer's note of what a self-built nginx's configuration includes: the
// daemon's user often cannot read that file (a panel keeps it to root), and
// doctor reads the note instead.
func TestIncludeNote(t *testing.T) {
	dir := t.TempDir()
	prev := IncludeNotePath
	IncludeNotePath = filepath.Join(dir, ".nginx-includes")
	t.Cleanup(func() { IncludeNotePath = prev })

	if _, _, found := IncludeNote(); found {
		t.Error("a note that is not there was found")
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(IncludeNotePath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("ok\n")
	miss, at, found := IncludeNote()
	if !found || len(miss) != 0 || at.IsZero() {
		t.Errorf("\"ok\": missing=%v at=%v found=%v, want none, a time, true", miss, at, found)
	}

	write("missing: main http\n")
	if miss, _, found := IncludeNote(); !found || len(miss) != 2 || miss[0] != "main" || miss[1] != "http" {
		t.Errorf("\"missing: main http\": missing=%v found=%v", miss, found)
	}
	write("missing: http\n")
	if miss, _, found := IncludeNote(); !found || len(miss) != 1 || miss[0] != "http" {
		t.Errorf("\"missing: http\": missing=%v found=%v", miss, found)
	}

	// Anything else says nothing: the note is in a tree the daemon's user
	// can reach into, so it is read for these words and no others.
	for _, body := range []string{"", "missing:\n", "missing: /etc/shadow\n", "fine\n"} {
		write(body)
		if miss, _, found := IncludeNote(); found {
			t.Errorf("%q was taken for a note (missing=%v)", body, miss)
		}
	}
}
