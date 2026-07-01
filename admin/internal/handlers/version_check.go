package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Release is one entry of the unmask changelog served by unmask.sh/api/version.
type Release struct {
	Version string `json:"version"`
	Date    string `json:"date"`
	Notes   string `json:"notes"`
}

type versionDoc struct {
	Latest   string    `json:"latest"`
	Releases []Release `json:"releases"`
}

// VersionStatus is the resolved update state rendered on the settings overview.
type VersionStatus struct {
	Current         string    // running version, normalized (no v-prefix / build suffix)
	Latest          string    // newest released version, or "" when unknown
	UpdateAvailable bool      // Latest is strictly newer than Current
	History         []Release // releases newer than Current, newest first
	Checked         bool      // a successful check has completed at least once
	// UpdateCommand is the distro-appropriate upgrade command, set ONLY when
	// unmask is actually installed through that package manager.  Empty for a
	// manual binary install (ManualInstall is then true) or an unknown distro.
	UpdateCommand string
	ManualInstall bool // installed outside the package manager -> no pkg command
}

var (
	vcMu       sync.Mutex
	vcDoc      versionDoc
	vcChecked  time.Time
	vcOK       bool
	vcInflight bool
	// versionRefreshDisabled stops the background fetch; tests set it so the
	// suite never reaches out to the network.
	versionRefreshDisabled bool
)

// versionStatus returns the cached update state, kicking a background refresh
// when the cache is stale.  It never blocks the request on the network: the
// page renders from the last known result and the next load reflects a fresh
// check.  Returns a Current-only status when the check URL is disabled.
func (h *Handler) versionStatus() VersionStatus {
	st := VersionStatus{Current: cleanVersion(h.Version)}
	url := h.cfg().VersionCheckURLResolved()
	if url == "" {
		return st // operator disabled the check
	}

	vcMu.Lock()
	doc, ok := vcDoc, vcOK
	if !versionRefreshDisabled && !vcInflight && time.Since(vcChecked) > 12*time.Hour {
		vcInflight = true
		go h.refreshVersion(url)
	}
	vcMu.Unlock()

	st.Checked = ok
	if !ok {
		return st
	}
	st.Latest = cleanVersion(doc.Latest)
	if st.Latest != "" && versionLess(st.Current, st.Latest) {
		st.UpdateAvailable = true
		for _, r := range doc.Releases {
			if versionLess(st.Current, cleanVersion(r.Version)) {
				st.History = append(st.History, r)
			}
		}
		// Only suggest a package command when unmask is really installed through
		// the package manager; a hand-placed binary has no package to upgrade.
		if fam, installed := unmaskPackageStatus(); installed {
			st.UpdateCommand = updateCommand(fam)
		} else {
			st.ManualInstall = true
		}
	}
	return st
}

func (h *Handler) refreshVersion(url string) {
	defer func() {
		vcMu.Lock()
		vcInflight = false
		vcMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var doc versionDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return
	}
	vcMu.Lock()
	vcDoc, vcOK, vcChecked = doc, true, time.Now()
	vcMu.Unlock()
}

// cleanVersion strips a leading "v" and any build / pre-release suffix so
// "v0.1.0-83b53d4" compares as "0.1.0".
func cleanVersion(s string) string {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v"))
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	return s
}

// versionLess reports a < b as dotted numeric versions (major.minor.patch).
func versionLess(a, b string) bool {
	pa, pb := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func parseVer(s string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(cleanVersion(s), ".", 3) {
		if i > 2 {
			break
		}
		out[i], _ = strconv.Atoi(strings.TrimSpace(p))
	}
	return out
}

var (
	pkgStatusOnce sync.Once
	pkgFamily     string
	pkgInstalled  bool
)

// unmaskPackageStatus detects the host package-manager family ("rpm" / "deb" /
// "apk") and whether the `unmask` package is actually registered with it.
// Cached: neither changes while the daemon runs.
func unmaskPackageStatus() (family string, installed bool) {
	pkgStatusOnce.Do(func() {
		pkgFamily = detectFamily("/etc/os-release")
		pkgInstalled = queryInstalled(pkgFamily, "unmask")
	})
	return pkgFamily, pkgInstalled
}

func detectFamily(osReleasePath string) string {
	b, err := os.ReadFile(osReleasePath)
	if err != nil {
		return ""
	}
	var id, like string
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"'`)
		case strings.HasPrefix(line, "ID_LIKE="):
			like = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"'`)
		}
	}
	hay := strings.ToLower(id + " " + like)
	switch {
	case strings.Contains(hay, "alpine"):
		return "apk"
	case containsAny(hay, "debian", "ubuntu"):
		return "deb"
	case containsAny(hay, "rhel", "fedora", "centos", "rocky", "almalinux", "alma"):
		return "rpm"
	}
	return ""
}

// queryInstalled returns true when the package manager reports name as
// installed.  Read-only query, short timeout; any error counts as "not via a
// package" (= a manual binary install).
func queryInstalled(family, name string) bool {
	var cmd string
	var args []string
	switch family {
	case "rpm":
		cmd, args = "rpm", []string{"-q", name}
	case "deb":
		cmd, args = "dpkg-query", []string{"-W", "-f=${Status}", name}
	case "apk":
		cmd, args = "apk", []string{"info", "-e", name}
	default:
		return false
	}
	if _, err := exec.LookPath(cmd); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd, args...).Output()
	if err != nil {
		return false
	}
	if family == "deb" {
		// dpkg-query prints "install ok installed" for a present package.
		return strings.Contains(string(out), "installed")
	}
	return true
}

func containsAny(hay string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// updateCommand returns the distro-appropriate command to upgrade the unmask
// package, or "" for an unknown family.
func updateCommand(family string) string {
	switch family {
	case "rpm":
		return "sudo dnf upgrade unmask"
	case "deb":
		return "sudo apt update && sudo apt install --only-upgrade unmask"
	case "apk":
		return "sudo apk update && sudo apk upgrade unmask"
	}
	return ""
}
