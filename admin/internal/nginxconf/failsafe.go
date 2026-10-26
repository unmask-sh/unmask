package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FailsafeMarker is the breadcrumb the plugin's place-module.sh leaves in the
// render dir when its fail-safe strips the native wiring -- no bundled module
// matches the host nginx, or `nginx -t` failed on something of unmask's.
// While it exists the module is not loaded, so the render must not name the
// module's directives or variables: Render reads it and writes the degraded
// configuration (renderData.Degraded).  place-module clears it on the next
// `nginx -t` that passes with the module wired, and renders again.
const FailsafeMarker = ".native-failsafe"

// FailsafePackageDir is where place-module.sh writes the marker: the
// package's render dir.  place-module reads no config.yml, so an install
// rendering elsewhere (nginx.output_dir) is still told through this path --
// the marker counts from either dir.  A variable so a test can point it at a
// scratch dir (the TestMains of the packages that render do, so a marker
// left on the test host cannot turn every render degraded).
var FailsafePackageDir = "/var/lib/unmask/nginx"

// failsafeMarkerPath is the marker that applies to a render into dir: the
// one in dir, else the one in FailsafePackageDir.
func failsafeMarkerPath(dir string) (string, bool) {
	for _, d := range []string{dir, FailsafePackageDir} {
		if d == "" {
			continue
		}
		p := filepath.Join(d, FailsafeMarker)
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

// FailsafeActive reports whether a render into dir is under the fail-safe:
// the marker is in dir, or in the package dir place-module writes to.
func FailsafeActive(dir string) bool {
	_, ok := failsafeMarkerPath(dir)
	return ok
}

// FailsafeState reads the marker that applies to dir (see FailsafeActive):
// whether there is one, the reason place-module wrote ("" when it gave
// none), and when it was written.
func FailsafeState(dir string) (active bool, reason string, since time.Time) {
	p, ok := failsafeMarkerPath(dir)
	if !ok {
		return false, "", time.Time{}
	}
	fi, err := os.Stat(p)
	if err != nil {
		return false, "", time.Time{}
	}
	b, err := os.ReadFile(p)
	if err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(ln, "reason:"); ok {
				reason = strings.TrimSpace(v)
				break
			}
		}
	}
	return true, reason, fi.ModTime()
}

// ReloadNeededMarker is written beside the rendered files by every render
// that changed one of them, with the render id the files now carry.  It says
// "nginx has not loaded this render yet" to whatever applies reloads -- the
// container gateway, an operator's tooling, the metrics -- and is removed
// once the access log shows nginx running that id (renderwatch.Settle).
// Written only where that log reaches the daemon (the native install and
// the container gateway); a forward-auth install sends none and gets no
// marker.  Config only: the module file changing is a restart matter, not
// this one.
const ReloadNeededMarker = ".reload-needed"

// writeReloadNeeded records that the render with id waits for a reload.
// Best effort, like the other markers: a marker that could not be written
// leaves the admin's own reload notice, which reads the log, as the signal.
func writeReloadNeeded(dir, id string) {
	_ = os.WriteFile(filepath.Join(dir, ReloadNeededMarker), []byte(id+"\n"), 0o644)
}

// ReloadNeeded reports whether a render in dir waits for a reload, and which
// (the id the marker names; "" from a marker without one).
func ReloadNeeded(dir string) (id string, waiting bool) {
	if dir == "" {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(dir, ReloadNeededMarker))
	if err != nil {
		return "", false
	}
	id, _, _ = strings.Cut(string(b), "\n")
	return strings.TrimSpace(id), true
}

// ClearReloadNeeded removes the marker in dir when it names id (or when id
// is "": whatever it names).  A marker naming another id is a newer render's,
// written after the verdict that led here, and stays.  Reports whether a
// marker was removed.
func ClearReloadNeeded(dir, id string) bool {
	if dir == "" {
		return false
	}
	cur, waiting := ReloadNeeded(dir)
	if !waiting || (id != "" && cur != id) {
		return false
	}
	return os.Remove(filepath.Join(dir, ReloadNeededMarker)) == nil
}
