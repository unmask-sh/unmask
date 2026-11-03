package ban

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The daemon opens directories (o+x) for nginx's worker only under the
// package's data directory.  A list the operator put elsewhere -- here a
// scratch directory, as a home directory would be -- keeps the modes above
// it; the list itself is still 0644.
func TestEnsureReadableLeavesDirectoriesOutsideTheDataRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root passes every directory")
	}
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "private")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sub, "ban.list")
	mgr := New(d, file, 0)
	if err := mgr.AddManualWithScope(context.Background(), "203.0.113.5", "", ScopeIPOnly, "test", "tester", "deny", 0); err != nil {
		t.Fatal(err)
	}
	mgr.settle()
	st, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf("the directory outside %s was changed to %#o", dataRoot, st.Mode().Perm())
	}
	fst, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fst.Mode().Perm() != 0o644 {
		t.Errorf("the list is %#o, want 0644", fst.Mode().Perm())
	}
}

func TestUnderDir(t *testing.T) {
	for path, want := range map[string]bool{
		"/var/lib/unmask":                 true,
		"/var/lib/unmask/nginx":           true,
		"/var/lib/unmask/nginx/../nginx":  true,
		"/var/lib/unmask2/nginx":          false,
		"/var/lib":                        false,
		"/home/op/unmask/nginx":           false,
		"/var/lib/unmask/../unmask-other": false,
	} {
		if got := underDir(path, dataRoot); got != want {
			t.Errorf("underDir(%q) = %v", path, got)
		}
	}
}
