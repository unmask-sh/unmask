package nginxlog

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/sockperm"
)

func dirMode(t *testing.T, socketPath string) os.FileMode {
	t.Helper()
	st, err := os.Stat(filepath.Dir(socketPath))
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func socketMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket", path)
	}
	return st.Mode().Perm()
}

// The access-log socket is shared with the worker by group: 0660, owned by
// the group named (here one the daemon may give it to, its own).  When the
// group cannot be applied the socket opens to every local user instead, so
// nginx's lines are not lost -- and the daemon says so in its log.
func TestStartSharesTheLogSocketByGroup(t *testing.T) {
	me, err := osuser.Current()
	if err != nil {
		t.Skip(err)
	}
	grp, err := osuser.LookupGroupId(me.Gid)
	if err != nil {
		t.Skip(err)
	}
	shared := sockPath(t, "shared.sock")
	r := StartWith(shared, handoverDB(t), sockperm.Spec{Group: grp.Name})
	defer r.Close()
	if got := socketMode(t, shared); got != 0o660 {
		t.Errorf("socket shared with %q has mode %#o, want 0660", grp.Name, got)
	}
	// The directory is shared by the same group, and by nobody else.
	if got := dirMode(t, shared); got != 0o750 {
		t.Errorf("the directory of the shared socket has mode %#o, want 0750", got)
	}

	open := sockPath(t, "open.sock")
	r2 := StartWith(open, handoverDB(t), sockperm.Spec{Group: "no-such-group-unmask-test"})
	defer r2.Close()
	if got := socketMode(t, open); got != 0o666 {
		t.Errorf("socket without an applicable group has mode %#o, want 0666", got)
	}
	// With no group the worker still has to pass through the directory.
	if got := dirMode(t, open); got != 0o755 {
		t.Errorf("the directory of the open socket has mode %#o, want 0755", got)
	}

	// An explicit mode is applied as it is.
	fixed := sockPath(t, "fixed.sock")
	r3 := StartWith(fixed, handoverDB(t), sockperm.Spec{Mode: "0600", Group: grp.Name})
	defer r3.Close()
	if got := socketMode(t, fixed); got != 0o600 {
		t.Errorf("socket with socket_mode 0600 has mode %#o", got)
	}
}
