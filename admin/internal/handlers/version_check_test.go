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

	h.SetSettings(settings.Settings{VersionCheckURL: "off"})
	if st := h.versionStatus(); st.Checked || st.UpdateAvailable {
		t.Error("a disabled check must report nothing")
	}
}
