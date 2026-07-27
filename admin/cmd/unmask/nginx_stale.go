package main

// Detection of "the running nginx still maps files that a package already
// replaced on disk".
//
// Why this is worth a check of its own: `nginx -s reload` re-reads the config
// but does NOT re-exec the master process.  When a package upgrade swaps a
// shared library (glibc, OpenSSL, an NSS module, a dynamic nginx module) under
// a running nginx, the master keeps the old, now-unlinked file mapped and every
// worker it forks inherits that image.  A reload therefore does not clear the
// stale mapping -- it hands live traffic to fresh workers built from the broken
// image, which can jump into an address the kernel no longer backs and die with
// SIGSEGV.  Only a restart replaces the master.
//
// Two known traps produce exactly this state, and both are covered here:
//   - the host upgrades an OS library (unattended-upgrades / dnf) and nginx is
//     only ever reloaded afterwards;
//   - unmask's own plugin package places a new ngx_http_unmask_module.so while
//     nginx is running.

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// nginxPIDFiles: where the master pid file lives across distros / prefixes.
// Tried before scanning /proc so the common case costs a single open().
var nginxPIDFiles = []string{
	"/run/nginx.pid",
	"/run/nginx/nginx.pid",
	"/var/run/nginx.pid",
	"/usr/local/nginx/logs/nginx.pid",
}

// procRoot is "/proc" in production; tests point it at a fixture tree.
var procRoot = "/proc"

// nginxMasterPID returns the pid of the running nginx master process, or 0 when
// none can be identified.
func nginxMasterPID() int {
	for _, f := range nginxPIDFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid <= 0 {
			continue
		}
		// A stale pid file can point at a recycled pid: confirm it is nginx.
		if strings.Contains(procCmdline(pid), "nginx") {
			return pid
		}
	}
	// No usable pid file (relocated prefix, container, foreground run): fall
	// back to the master's distinctive rewritten argv.
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return 0
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if strings.Contains(procCmdline(pid), "nginx: master process") {
			return pid
		}
	}
	return 0
}

func procCmdline(pid int) string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	// argv is NUL-separated; nginx rewrites its own into one readable string.
	return strings.ReplaceAll(string(b), "\x00", " ")
}

// staleNginxLibs lists the shared libraries (and nginx binaries) the running
// nginx master is still executing from files that no longer match what is on
// disk -- the state only a restart clears.
//
// A deleted mapping alone is not enough to report.  Placing a module or
// reinstalling a package rewrites the file through a temp name and rename(2)
// (the ETXTBSY-safe way to replace a .so a running process has mapped), so a
// reinstall of the SAME build leaves exactly this mapping shape while the bytes
// in memory are current.  Measured on the fleet, that accounts for most of what
// the deleted marker finds: 4 of 7 hosts carried a deleted module whose content
// was byte-identical to the file on disk.  Reporting those would leave a
// warning permanently lit on healthy hosts, which is how a diagnostic stops
// being read before the run that matters.  So each candidate is compared
// against the current file and dropped when the bytes match.
//
// checked reports whether the answer means anything: false = the running nginx
// could not be inspected at all (not running, or /proc/<pid>/maps belongs to
// root and this process is not).  Callers must stay silent on false rather than
// report the install as clean -- an unreadable maps file proves nothing.
func staleNginxLibs() (paths []string, checked bool) {
	pid := nginxMasterPID()
	if pid == 0 {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil, false
	}
	// First mapping of each path carries the address range that names it under
	// map_files, which is the only handle left on an unlinked inode.
	addrOf := map[string]string{}
	var order []string
	for _, ln := range strings.Split(string(b), "\n") {
		const marker = " (deleted)"
		if !strings.HasSuffix(ln, marker) {
			continue
		}
		// maps line: "<range> <perms> <offset> <dev> <inode>  <path>"
		f := strings.Fields(ln)
		if len(f) < 6 {
			continue
		}
		p := strings.TrimSuffix(strings.Join(f[5:], " "), marker)
		if !replaceableOnDisk(p) {
			continue
		}
		if _, dup := addrOf[p]; dup {
			continue
		}
		addrOf[p] = f[0]
		order = append(order, p)
	}
	for _, p := range order {
		if same, compared := runningMatchesDisk(pid, addrOf[p], p); compared && same {
			continue // replaced with identical bytes -- nothing to apply
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, true
}

// runningMatchesDisk reports whether the bytes the process still has mapped are
// identical to the file now at that path.
//
// compared=false means the question could not be settled: /proc/<pid>/map_files
// needs CAP_SYS_ADMIN (stricter than the maps file itself), and the path may be
// gone entirely.  The caller then KEEPS the finding -- a difference that cannot
// be ruled out must not be silently dismissed, and the fix (a restart) is the
// same either way.
func runningMatchesDisk(pid int, addr, path string) (same, compared bool) {
	running, err := hashFile(filepath.Join(procRoot, strconv.Itoa(pid), "map_files", addr))
	if err != nil {
		return false, false
	}
	onDisk, err := hashFile(path)
	if err != nil {
		return false, false
	}
	return running == onDisk, true
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// replaceableOnDisk reports whether a mapped path is a real on-disk executable
// artifact -- a shared library or an nginx binary.
//
// This is an ALLOWLIST on purpose.  A healthy nginx always carries deleted
// mappings that mean nothing is wrong (/dev/zero backs the shared-memory zones,
// /[aio] the AIO ring, plus memfd / SysV shm), and a denylist would have to
// grow every time the kernel names a new one -- one wrong entry turns this into
// a false alarm on every run, which is how a diagnostic loses its audience.
func replaceableOnDisk(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	base := filepath.Base(p)
	if base == "nginx" {
		return true
	}
	// libfoo.so, libfoo.so.6, libfoo.so.1.2.11, a module's ngx_*.so
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")
}

// staleNginxLibsList renders the reported paths for a one-line message: up to
// three names, then "+N more".  Shared by the doctor check and the
// render-nginx hint so the two never drift.
func staleNginxLibsList(paths []string) string {
	const max = 3
	shown := paths
	extra := 0
	if len(shown) > max {
		extra = len(shown) - max
		shown = shown[:max]
	}
	names := make([]string, 0, len(shown))
	for _, p := range shown {
		names = append(names, filepath.Base(p))
	}
	s := strings.Join(names, ", ")
	if extra > 0 {
		s += ", +" + strconv.Itoa(extra) + " more"
	}
	return s
}
