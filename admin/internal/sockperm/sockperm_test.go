package sockperm

import (
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestParseFileMode(t *testing.T) {
	for in, want := range map[string]os.FileMode{"": 0o660, "0660": 0o660, "660": 0o660, "0666": 0o666, " 0600 ": 0o600} {
		got, err := ParseFileMode(in, 0o660)
		if err != nil || got != want {
			t.Errorf("ParseFileMode(%q) = %#o, %v; want %#o", in, got, err, want)
		}
	}
	if got, err := ParseFileMode("rw-rw----", 0o660); err == nil || got != 0o660 {
		t.Errorf("a non-octal mode must fail and fall back: %#o, %v", got, err)
	}
}

// The probe returns a name from its own list, and every name it lists as
// existing does exist.
func TestDetectWebServerGroupAnswersFromItsList(t *testing.T) {
	g, all := DetectWebServerGroup()
	if g == "" {
		if all != nil {
			t.Fatalf("no group, yet a list: %v", all)
		}
		return
	}
	if all[0] != g {
		t.Errorf("first = %q, list = %v", g, all)
	}
	for _, name := range all {
		if _, err := osuser.LookupGroup(name); err != nil {
			t.Errorf("%q listed as existing: %v", name, err)
		}
		found := false
		for _, cand := range WebServerGroups {
			found = found || cand == name
		}
		if !found {
			t.Errorf("%q is not one of the probed names", name)
		}
	}
}

// The group nginx.conf names for its workers comes ahead of the list -- the
// first listed group that exists is not always the worker's -- and only when
// it is a group of this host.
func TestDetectWebServerGroupPrefersTheWorkersGroup(t *testing.T) {
	t.Cleanup(func() { WorkerGroup = nil })
	me, err := osuser.Current()
	if err != nil {
		t.Skip(err)
	}
	mine, err := osuser.LookupGroupId(me.Gid)
	if err != nil {
		t.Skip(err)
	}
	listed, listedAll := DetectWebServerGroup()

	WorkerGroup = func() string { return " " + mine.Name + " " }
	g, all := DetectWebServerGroup()
	if g != mine.Name || len(all) != 1 || all[0] != mine.Name {
		t.Errorf("the worker's group %q: got %q %v", mine.Name, g, all)
	}

	// A name that is no group here, or no answer: the list, as without it.
	for _, answer := range []string{"no-such-group-unmask-test", ""} {
		WorkerGroup = func() string { return answer }
		g, all = DetectWebServerGroup()
		if g != listed || len(all) != len(listedAll) {
			t.Errorf("worker group %q: got %q %v, want the list's %q %v", answer, g, all, listed, listedAll)
		}
	}
}

func bindSocket(t *testing.T) string {
	t.Helper()
	// Short path: a unix socket path is limited to about a hundred bytes.
	dir, err := os.MkdirTemp("", "sp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return path
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// A group the daemon may give the socket to (its own primary group, here):
// the socket is shared by group at 0660.
func TestApplySharesByGroup(t *testing.T) {
	me, err := osuser.Current()
	if err != nil {
		t.Skip(err)
	}
	grp, err := osuser.LookupGroupId(me.Gid)
	if err != nil {
		t.Skip(err)
	}
	path := bindSocket(t)
	res, err := Apply(path, Spec{Group: grp.Name}, 0o660, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != 0o660 || res.Group != grp.Name || res.WorldWritable() {
		t.Fatalf("result %+v, want 0660 shared with %q", res, grp.Name)
	}
	if got := modeOf(t, path); got != 0o660 {
		t.Errorf("socket mode %#o", got)
	}
}

// A group that cannot be applied: the log socket (loosen) opens to everyone
// and says why; the admin listener (no loosen) keeps 0660 and says why.
func TestApplyWithoutAnApplicableGroup(t *testing.T) {
	path := bindSocket(t)
	res, err := Apply(path, Spec{Group: "no-such-group-unmask-test"}, 0o660, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.WorldWritable() || res.Group != "" || modeOf(t, path) != 0o666 {
		t.Fatalf("loosened result %+v, mode %#o; want 0666 and no group", res, modeOf(t, path))
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "0666") {
		t.Errorf("notes = %v, want the one about opening the socket", res.Notes)
	}

	res, err = Apply(path, Spec{Group: "no-such-group-unmask-test"}, 0o660, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.WorldWritable() || modeOf(t, path) != 0o660 {
		t.Fatalf("strict result %+v, mode %#o; want 0660 kept", res, modeOf(t, path))
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "lookup failed") {
		t.Errorf("notes = %v, want the lookup failure", res.Notes)
	}
}

// A world-writable mode asked for by the operator is applied as it is, with
// no group probe.
func TestApplyExplicitWorldWritable(t *testing.T) {
	path := bindSocket(t)
	res, err := Apply(path, Spec{Mode: "0666"}, 0o660, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.WorldWritable() || res.Group != "" || len(res.Notes) != 0 || modeOf(t, path) != 0o666 {
		t.Fatalf("result %+v, mode %#o", res, modeOf(t, path))
	}
}

// The socket's directory is shared the same way: 0750 by the socket's
// group when there is one, 0755 when there is not (the worker still has to
// pass through), and a directory the daemon does not own is left alone.
func TestShareDir(t *testing.T) {
	me, err := osuser.Current()
	if err != nil {
		t.Skip(err)
	}
	grp, err := osuser.LookupGroupId(me.Gid)
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	mode, notes := ShareDir(dir, grp.Name)
	if mode != 0o750 || len(notes) != 0 || modeOf(t, dir) != 0o750 {
		t.Fatalf("shared with %q: mode %#o, notes %v, on disk %#o", grp.Name, mode, notes, modeOf(t, dir))
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if gid := st.Sys().(*syscall.Stat_t).Gid; strconv.Itoa(int(gid)) != me.Gid {
		t.Errorf("directory gid %d, want %s", gid, me.Gid)
	}

	mode, notes = ShareDir(dir, "")
	if mode != 0o755 || len(notes) != 1 || !strings.Contains(notes[0], "0755") || modeOf(t, dir) != 0o755 {
		t.Errorf("no group: mode %#o, notes %v, on disk %#o", mode, notes, modeOf(t, dir))
	}
	mode, notes = ShareDir(dir, "no-such-group-unmask-test")
	if mode != 0o755 || len(notes) != 1 || !strings.Contains(notes[0], "cannot give") {
		t.Errorf("unknown group: mode %#o, notes %v", mode, notes)
	}

	if os.Getuid() != 0 {
		before := modeOf(t, "/")
		if mode, notes := ShareDir("/", grp.Name); mode != before || len(notes) != 0 || modeOf(t, "/") != before {
			t.Errorf("a directory of another owner: mode %#o, notes %v", mode, notes)
		}
	}
}
