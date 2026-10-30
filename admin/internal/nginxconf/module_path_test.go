package nginxconf

import (
	"os"
	"path/filepath"
	"testing"
)

// The module's path is read the way place-module.sh wires it: a load_module
// line in nginx.conf itself, or in a file of a main-context include named
// ahead of the http block -- quotes and the placer's comment dropped -- and
// nothing where none is wired.
func TestModuleFilePathFollowsTheWiring(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "modules-enabled")
	if err := os.MkdirAll(inc, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "nginx.conf")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(conf, "user nginx;\n# load_module \"/old/ngx_http_unmask_module.so\";\ninclude "+inc+"/*.conf;\nevents {}\nhttp {\n    load_module \"/not/here/ngx_http_unmask_module.so\";\n}\n")
	write(filepath.Join(inc, "10-other.conf"), "load_module /usr/lib64/nginx/modules/ngx_http_image_filter_module.so;\n")
	write(filepath.Join(inc, "50-mod-unmask.conf"), "load_module \"/usr/lib64/nginx/modules/ngx_http_unmask_module.so\";  # unmask-plugin-nginx: auto-added, removed on uninstall\n")
	if got := ModuleFilePath(conf); got != "/usr/lib64/nginx/modules/ngx_http_unmask_module.so" {
		t.Errorf("drop-in in the include dir: %q", got)
	}
	// A relative include is read against nginx.conf's directory.
	write(conf, "include modules-enabled/*.conf;\nhttp {\n}\n")
	if got := ModuleFilePath(conf); got != "/usr/lib64/nginx/modules/ngx_http_unmask_module.so" {
		t.Errorf("relative include: %q", got)
	}
	// nginx.conf's own line wins, unquoted.
	write(conf, "load_module /var/lib/unmask/plugin/ngx_http_unmask_module.so;\ninclude "+inc+"/*.conf;\nhttp {\n}\n")
	if got := ModuleFilePath(conf); got != "/var/lib/unmask/plugin/ngx_http_unmask_module.so" {
		t.Errorf("nginx.conf's own line: %q", got)
	}
	// Nothing wired: nothing named.
	write(conf, "include "+inc+"/10-other.conf;\nhttp {\n}\n")
	if got := ModuleFilePath(conf); got != "" {
		t.Errorf("no unmask load_module: %q, want none", got)
	}
	if got := ModuleFilePath(filepath.Join(dir, "missing.conf")); got != "" {
		t.Errorf("no nginx.conf: %q, want none", got)
	}
}
