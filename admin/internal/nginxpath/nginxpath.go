// Package nginxpath says where the nginx on this host keeps its main
// configuration file, and with that whose nginx it is.
//
// A distribution's nginx reads /etc/nginx/nginx.conf, and the packages wire
// unmask into the directories that file includes.  An nginx built from
// source -- by hand under /usr/local/nginx, by a hosting panel under a
// prefix of its own -- reads another file, and the packages leave that one
// alone: they keep directories of their own, which the operator includes
// once (OwnMainDir, OwnHTTPDir; rpm/scripts carries the same rule in its
// nginx-layout block).  The daemon has to read the right file for the same
// questions it asks of a distribution's: which user the workers run as, where
// the module is loaded from, whether map_hash sizes are already set.
package nginxpath

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Packaged is the configuration file of a distribution's nginx.
const Packaged = "/etc/nginx/nginx.conf"

// The directories of unmask's own that a self-built nginx includes: the one
// that loads the module (main context) and the one that carries the rendered
// configuration (inside http {}).
const (
	OwnMainDir = "/usr/share/unmask/nginx/modules-enabled"
	OwnHTTPDir = "/usr/share/unmask/nginx/conf.d"
)

// defaultPrefix is where nginx installs itself when its configure line
// names no --prefix.
const defaultPrefix = "/usr/local/nginx"

// probeTTL is how long an answer of `nginx -V` is kept: the daemon asks on
// every render and every admin page that names the file, and the answer
// changes only when nginx is installed anew.
const probeTTL = time.Minute

var (
	mu       sync.Mutex
	probedAt time.Time
	probed   string

	// versionOutput is `nginx -V`; a test puts its own in its place.
	versionOutput = func() (string, bool) {
		bin, err := exec.LookPath("nginx")
		if err != nil {
			return "", false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// nginx -V writes to stderr and exits 0; what it printed is what counts.
		out, _ := exec.CommandContext(ctx, bin, "-V").CombinedOutput()
		return string(out), true
	}
)

// ConfPath is the main configuration file to read: the one the operator
// configured (nginx.conf_path) when there is one, else the file the nginx on
// PATH was built to read, else Packaged -- when there is no nginx to ask, or
// none that answers like one.
func ConfPath(configured string) string {
	if c := strings.TrimSpace(configured); c != "" {
		return c
	}
	mu.Lock()
	defer mu.Unlock()
	if probed != "" && time.Since(probedAt) < probeTTL {
		return probed
	}
	p := Packaged
	if out, ok := versionOutput(); ok {
		p = FromVersionOutput(out)
	}
	probed, probedAt = p, time.Now()
	return p
}

// SelfBuilt reports whether the nginx on PATH is one built from source:
// its configuration file is not the distributions'.  configured is
// nginx.conf_path; an operator who points it at Packaged has said the nginx
// is laid out like a distribution's.
func SelfBuilt(configured string) bool {
	return ConfPath(configured) != Packaged
}

// FromVersionOutput reads the configuration file out of what `nginx -V`
// printed: --conf-path, or conf/nginx.conf under --prefix, or under nginx's
// own default prefix; a relative --conf-path is under the prefix.  Packaged
// when the text carries no configure line (not an nginx, or one that could
// not be run).
func FromVersionOutput(out string) string {
	i := strings.Index(out, "configure arguments:")
	if i < 0 {
		return Packaged
	}
	var conf, prefix string
	for _, f := range strings.Fields(out[i+len("configure arguments:"):]) {
		switch {
		case strings.HasPrefix(f, "--conf-path=") && conf == "":
			conf = strings.TrimPrefix(f, "--conf-path=")
		case strings.HasPrefix(f, "--prefix=") && prefix == "":
			prefix = strings.TrimPrefix(f, "--prefix=")
		}
	}
	if prefix == "" {
		prefix = defaultPrefix
	}
	switch {
	case strings.HasPrefix(conf, "/"):
		return conf
	case conf == "":
		return prefix + "/conf/nginx.conf"
	default:
		return prefix + "/" + conf
	}
}

// includeRE: one `include <path>;`, wherever it stands on the line (comments
// are dropped before it is applied).
var includeRE = regexp.MustCompile("(?:^|[\\s;{}])include\\s+[\"']?([^\\s;\"']+)[\"']?\\s*;")

// MissingOwnIncludes reads the configuration of a self-built nginx --
// confPath and the files it includes, masks expanded and relative paths read
// against confPath's directory, as nginx reads them -- and reports which of
// unmask's two directories it does not include: the one that loads the
// module, the one inside http {}.  readable is false when confPath itself
// cannot be read, and nothing is then known about either.  unread lists the
// included files that could not be read (the daemon's user is not root, and
// a panel may keep its sites' files to itself): a line reported missing may
// be in one of those.
//
// Where the line stands is not checked (the first is for the main context,
// the second for http {}): `nginx -t` says so when one is misplaced.
func MissingOwnIncludes(confPath string) (noMain, noHTTP, readable bool, unread []string) {
	if _, err := os.ReadFile(confPath); err != nil {
		return true, true, false, nil
	}
	noMain, noHTTP = true, true
	base := filepath.Dir(confPath)
	seen := map[string]bool{}
	level := []string{confPath}
	// Six levels: an include that leads back to itself ends here.
	for depth := 0; depth < 6 && len(level) > 0 && (noMain || noHTTP); depth++ {
		var next []string
		for _, f := range level {
			if seen[f] {
				continue
			}
			seen[f] = true
			b, err := os.ReadFile(f)
			if err != nil {
				unread = append(unread, f)
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				if i := strings.IndexByte(line, '#'); i >= 0 {
					line = line[:i]
				}
				for _, m := range includeRE.FindAllStringSubmatch(line, -1) {
					switch m[1] {
					case OwnMainDir + "/*.conf":
						noMain = false
						continue
					case OwnHTTPDir + "/*.conf":
						noHTTP = false
						continue
					}
					pat := m[1]
					if !filepath.IsAbs(pat) {
						pat = filepath.Join(base, pat)
					}
					files, _ := filepath.Glob(pat)
					next = append(next, files...)
				}
			}
		}
		level = next
	}
	return noMain, noHTTP, true, unread
}

// resetProbe forgets the cached answer (tests).
func resetProbe() {
	mu.Lock()
	probed, probedAt = "", time.Time{}
	mu.Unlock()
}
