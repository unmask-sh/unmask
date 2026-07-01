// Guards the include-aware host probe (C1): hostHasVariablesHash must see a
// variables_hash_* a host declared in an INCLUDED file (the ubiquitous
// conf.d/*.conf), not just the literal nginx.conf -- an include-blind scan
// missed it and unmask emitted a duplicate, tripping nginx -t + the plugin
// fail-safe (silent unprotect).  It must NOT count unmask's OWN rendered output
// (http.inc under OutputDir, reached via the conf.d/00-unmask.conf symlink), or
// it would self-detect and under-emit on re-render.
package nginxconf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestHostHasVariablesHashFollowsIncludes(t *testing.T) {
	// write builds a host nginx.conf tree in a temp dir and returns Settings
	// pointing at it.  `confd` = files dropped in conf.d/ (host includes);
	// `unmaskHTTPInc` (if non-empty) = the content of unmask's OWN rendered
	// http.inc under OutputDir, symlinked into conf.d as 00-unmask.conf.
	write := func(t *testing.T, mainConf string, confd map[string]string, unmaskHTTPInc string) settings.Settings {
		t.Helper()
		dir := t.TempDir()
		confPath := filepath.Join(dir, "nginx.conf")
		if err := os.WriteFile(confPath, []byte(mainConf), 0o644); err != nil {
			t.Fatal(err)
		}
		cd := filepath.Join(dir, "conf.d")
		if err := os.MkdirAll(cd, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range confd {
			if err := os.WriteFile(filepath.Join(cd, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		out := filepath.Join(dir, "out")
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Fatal(err)
		}
		if unmaskHTTPInc != "" {
			httpInc := filepath.Join(out, "http.inc")
			if err := os.WriteFile(httpInc, []byte(unmaskHTTPInc), 0o644); err != nil {
				t.Fatal(err)
			}
			// mimic the package's conf.d/00-unmask.conf -> OutputDir/http.inc symlink
			if err := os.Symlink(httpInc, filepath.Join(cd, "00-unmask.conf")); err != nil {
				t.Fatal(err)
			}
		}
		var s settings.Settings
		s.Nginx.ConfPath = confPath
		s.Nginx.OutputDir = out
		return s
	}

	t.Run("declared in nginx.conf itself", func(t *testing.T) {
		s := write(t, "variables_hash_max_size 2048;\nhttp {\n}\n", nil, "")
		if !hostHasVariablesHash(s) {
			t.Error("must detect variables_hash declared in nginx.conf")
		}
	})

	t.Run("declared in an included conf.d file", func(t *testing.T) {
		s := write(t, "", map[string]string{"tuning.conf": "variables_hash_bucket_size 128;\n"}, "")
		// rewrite nginx.conf to include the conf.d glob (needs the temp dir path)
		confPath := s.Nginx.ConfPath
		body := "http {\n    include " + filepath.Join(filepath.Dir(confPath), "conf.d", "*.conf") + ";\n}\n"
		if err := os.WriteFile(confPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if !hostHasVariablesHash(s) {
			t.Error("must follow `include conf.d/*.conf` and detect the host directive there")
		}
	})

	t.Run("unmask's own http.inc under OutputDir is NOT counted", func(t *testing.T) {
		s := write(t, "", nil, "variables_hash_max_size 4096;\nmap_hash_bucket_size 256;\n")
		confPath := s.Nginx.ConfPath
		body := "http {\n    include " + filepath.Join(filepath.Dir(confPath), "conf.d", "*.conf") + ";\n}\n"
		if err := os.WriteFile(confPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if hostHasVariablesHash(s) {
			t.Error("must NOT count unmask's own rendered http.inc (would under-emit on re-render)")
		}
	})

	t.Run("declared nowhere", func(t *testing.T) {
		s := write(t, "http {\n    server { listen 80; }\n}\n", map[string]string{"x.conf": "# nothing\n"}, "")
		confPath := s.Nginx.ConfPath
		body := "http {\n    include " + filepath.Join(filepath.Dir(confPath), "conf.d", "*.conf") + ";\n}\n"
		if err := os.WriteFile(confPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if hostHasVariablesHash(s) {
			t.Error("no variables_hash anywhere -> must be false (unmask emits its own)")
		}
	})
}
