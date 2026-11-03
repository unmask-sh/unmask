package sockperm

import (
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
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
