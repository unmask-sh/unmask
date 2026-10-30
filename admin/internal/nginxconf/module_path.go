package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
)

// ModuleFilePath: where the host nginx loads the unmask module from -- the
// path of the first load_module directive naming ngx_http_unmask_module, in
// nginx.conf (confPath; /etc/nginx/nginx.conf when "") or in a file of a
// main-context include it names ahead of its http block, which is where
// place-module.sh wires the module (modules-enabled/, /usr/share/nginx/modules/).
// "" when none is wired: a forward-auth install, the fail-safe that stripped
// the module, the gateway container whose nginx lives elsewhere.  The daemon
// hashes the file there to tell, from the access log, whether the running
// nginx loaded it (renderwatch).
func ModuleFilePath(confPath string) string {
	confPath = strings.TrimSpace(confPath)
	if confPath == "" {
		confPath = "/etc/nginx/nginx.conf"
	}
	b, err := os.ReadFile(confPath)
	if err != nil {
		return ""
	}
	var includes []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "http") && strings.Contains(line, "{") {
			break // main context ends; load_module is not valid below
		}
		if p := loadModulePath(line); p != "" {
			return p
		}
		if rest, ok := strings.CutPrefix(line, "include"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			pat := strings.Trim(strings.TrimSuffix(strings.TrimSpace(rest), ";"), `"'`)
			if pat != "" && !filepath.IsAbs(pat) {
				pat = filepath.Join(filepath.Dir(confPath), pat)
			}
			if pat != "" {
				includes = append(includes, pat)
			}
		}
	}
	for _, pat := range includes {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			ib, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(ib), "\n") {
				if p := loadModulePath(strings.TrimSpace(line)); p != "" {
					return p
				}
			}
		}
	}
	return ""
}

// loadModulePath: the path a `load_module <path>;` line names when it loads
// the unmask module, "" otherwise.  Quotes and a trailing comment (the one
// place-module.sh adds) are dropped.
func loadModulePath(line string) string {
	rest, ok := strings.CutPrefix(line, "load_module")
	if !ok || rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return ""
	}
	if i := strings.Index(rest, "#"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSpace(rest)
	rest = strings.TrimSuffix(rest, ";")
	rest = strings.Trim(strings.TrimSpace(rest), `"'`)
	if !strings.Contains(filepath.Base(rest), "ngx_http_unmask_module") {
		return ""
	}
	return rest
}
