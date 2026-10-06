package handlers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Never reach the network from the test suite.
func init() { versionRefreshDisabled = true }

func TestCleanAndCompareVersions(t *testing.T) {
	if got := cleanVersion("v0.1.0-83b53d4"); got != "0.1.0" {
		t.Errorf("cleanVersion = %q, want 0.1.0", got)
	}
	if !versionLess("0.1.0", "0.2.0") || !versionLess("0.1.9", "0.2.0") || !versionLess("0.9.0", "1.0.0") {
		t.Error("expected a < b")
	}
	if versionLess("0.2.0", "0.1.0") || versionLess("0.1.0", "0.1.0") {
		t.Error("did not expect a < b")
	}
	if !versionLess(cleanVersion("v0.1.0-abc"), "0.1.1") {
		t.Error("build suffix must be ignored when comparing")
	}

	// A testing build keeps its tag, and sorts above the release before it and
	// below its own final release.
	if got := cleanVersion("0.1.50-rc1"); got != "0.1.50-rc1" {
		t.Errorf("cleanVersion = %q, want 0.1.50-rc1", got)
	}
	for _, c := range [][2]string{
		{"0.1.49", "0.1.50-rc1"},
		{"0.1.50-rc1", "0.1.50"},
		{"0.1.50-rc1", "0.1.50-rc2"},
		{"0.1.50-rc2", "0.1.51"},
	} {
		if !versionLess(c[0], c[1]) {
			t.Errorf("want %s < %s", c[0], c[1])
		}
		if versionLess(c[1], c[0]) {
			t.Errorf("did not want %s < %s", c[1], c[0])
		}
	}
	if versionLess("0.1.50-rc1", "0.1.50-rc1") {
		t.Error("an rc is not older than itself")
	}
}

func TestDetectFamily(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ content, want string }{
		{"ID=rocky\nID_LIKE=\"rhel centos fedora\"\n", "rpm"},
		{"ID=ubuntu\nID_LIKE=debian\n", "deb"},
		{"ID=debian\n", "deb"},
		{"ID=alpine\n", "apk"},
		{"ID=plan9\n", ""},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "osr")
		if err := os.WriteFile(p, []byte(c.content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := detectFamily(p); got != c.want {
			t.Errorf("case %d: detectFamily=%q want %q", i, got, c.want)
		}
	}
	if detectFamily(filepath.Join(dir, "absent")) != "" {
		t.Error("missing os-release should yield an empty family")
	}
}

func TestUpdateCommand(t *testing.T) {
	for _, fam := range []string{"rpm", "deb", "apk"} {
		if updateCommand(fam) == "" {
			t.Errorf("family %q must return a command", fam)
		}
	}
	if updateCommand("") != "" {
		t.Error("unknown family must return an empty command")
	}
}

func TestVersionStatus(t *testing.T) {
	seed := func(latest string, rels []Release, ok bool) {
		vcMu.Lock()
		vcDoc = versionDoc{Latest: latest, Releases: rels}
		vcOK = ok
		vcChecked = time.Now() // fresh -> versionStatus won't try to refresh
		vcMu.Unlock()
	}
	t.Cleanup(func() { seed("", nil, false) })

	h := &Handler{Version: "0.1.0"}
	h.SetSettings(settings.Settings{})

	seed("0.2.0", []Release{
		{Version: "0.2.0", Date: "2026-07-01", Notes: "new"},
		{Version: "0.1.0", Date: "2026-06-14", Notes: "init"},
	}, true)
	st := h.versionStatus()
	if !st.UpdateAvailable || st.Latest != "0.2.0" {
		t.Fatalf("want an update to 0.2.0, got %+v", st)
	}
	if len(st.History) != 1 || st.History[0].Version != "0.2.0" {
		t.Errorf("history should hold only the newer release, got %+v", st.History)
	}

	seed("0.1.0", []Release{{Version: "0.1.0"}}, true)
	if st := h.versionStatus(); st.UpdateAvailable {
		t.Error("0.1.0 vs 0.1.0 must not be an update")
	}

	// An install on a testing build shows the rc, is current while the rc is
	// ahead of the latest release, and is told when that release ships.
	rc := &Handler{Version: "0.1.50-rc1"}
	rc.SetSettings(settings.Settings{})
	seed("0.1.49", []Release{{Version: "0.1.49"}}, true)
	if st := rc.versionStatus(); st.Current != "0.1.50-rc1" || st.UpdateAvailable {
		t.Errorf("rc ahead of the latest release: got %+v", st)
	}
	seed("0.1.50", []Release{{Version: "0.1.50"}, {Version: "0.1.49"}}, true)
	if st := rc.versionStatus(); !st.UpdateAvailable || len(st.History) != 1 || st.History[0].Version != "0.1.50" {
		t.Errorf("rc1 once 0.1.50 ships: want an update to 0.1.50, got %+v", st)
	}

	h.SetSettings(settings.Settings{VersionCheckDisabled: true})
	if st := h.versionStatus(); st.Checked || st.UpdateAvailable {
		t.Error("a disabled check must report nothing")
	}
}
