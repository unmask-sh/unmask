package repocheck

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The forward-auth handlers take "which visitor is this about" from the
// X-Original-* headers: the proxy sets them on its subrequest, and the daemon
// believes them.  A location that proxies a visitor's request to the daemon
// with the visitor's own headers hands the daemon the visitor's claims
// instead -- another address to judge (and to ban, on a honeypot path),
// another URL, another site.  So every such location in the nginx
// configurations we ship overwrites the four the handlers act on with nginx's
// own values.  The packaged configuration always did; the copy-paste snippet's
// catch-all forwarded them as sent.

// faLocation is one top-level `location` block of an nginx configuration file.
type faLocation struct {
	spec string // "^~ /unmask/", "= /_unmask/check", "@unmask_challenge"
	body string // directives, comments stripped
}

var faLocationRE = regexp.MustCompile(`(?m)^location\s+([^{]+?)\s*\{`)

// faLocations lifts the top-level location blocks out of an nginx file.
// Comment lines go first, so a commented-out example block is not a block.
func faLocations(t *testing.T, rel string) []faLocation {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(self), "..", "..", "..", rel)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	src := strings.Join(kept, "\n")
	var out []faLocation
	for _, m := range faLocationRE.FindAllStringSubmatchIndex(src, -1) {
		depth, end := 1, -1
		for i := m[1]; i < len(src); i++ {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				end = i
				break
			}
		}
		if end < 0 {
			t.Fatalf("%s: location %q is not closed", rel, src[m[2]:m[3]])
		}
		out = append(out, faLocation{spec: strings.Join(strings.Fields(src[m[2]:m[3]]), " "), body: src[m[1]:end]})
	}
	if len(out) == 0 {
		t.Fatalf("%s: no location blocks found", rel)
	}
	return out
}

// faHeadersActedOn: what the handlers behind these locations read as the
// visitor's (auth_check.go, force_entry.go, handlers.go).
var faHeadersActedOn = []string{"X-Original-Host", "X-Original-URI", "X-Original-IP", "X-Original-UA"}

// faNoOriginalHeaders: locations whose handlers read none of them -- files,
// the probes, and the ban page (which shows the address and User-Agent nginx
// itself reports).
var faNoOriginalHeaders = map[string]bool{
	"^~ /unmask/static/": true,
	"= /unmask/metrics":  true,
	"= /unmask/healthz":  true,
	"= /unmask/readyz":   true,
	"@unmask_blocked":    true,
}

func TestForwardAuthConfsOverwriteOriginalHeaders(t *testing.T) {
	for _, rel := range []string{
		"snippets/nginx-forward-auth.conf",
		"rpm/conf/forward-auth/server.inc",
	} {
		proxied := 0
		for _, loc := range faLocations(t, rel) {
			if !strings.Contains(loc.body, "proxy_pass ") {
				continue
			}
			proxied++
			if faNoOriginalHeaders[loc.spec] {
				continue
			}
			var missing []string
			for _, h := range faHeadersActedOn {
				if !regexp.MustCompile(`(?m)^\s*proxy_set_header\s+` + regexp.QuoteMeta(h) + `\s+\S`).MatchString(loc.body) {
					missing = append(missing, h)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				t.Errorf("%s: location %s proxies to the daemon without overwriting %s: a visitor's own value reaches the forward-auth handlers",
					rel, loc.spec, strings.Join(missing, ", "))
			}
		}
		if proxied < 3 {
			t.Errorf("%s: only %d proxying locations found; the parser lost the file's shape", rel, proxied)
		}
	}
}

// The decision endpoint itself is kept from visitors by name, in every nginx
// configuration we ship, and the subrequest that does reach it is internal.
func TestForwardAuthConfsBlockTheDecisionEndpoint(t *testing.T) {
	for _, rel := range []string{
		"snippets/nginx-forward-auth.conf",
		"rpm/conf/forward-auth/server.inc",
	} {
		var blocked, internal bool
		for _, loc := range faLocations(t, rel) {
			switch loc.spec {
			case "= /unmask/api/check":
				blocked = strings.Contains(loc.body, "return 404")
			case "= /_unmask/check":
				internal = regexp.MustCompile(`(?m)^\s*internal\s*;`).MatchString(loc.body)
			}
		}
		if !blocked {
			t.Errorf("%s: no `location = /unmask/api/check { return 404; }`", rel)
		}
		if !internal {
			t.Errorf("%s: /_unmask/check is not marked internal", rel)
		}
	}
}
