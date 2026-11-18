package handlers

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The wizard's SQLite field takes a path, and the step that saves it opens
// the database to try the connection -- which creates the file.  The field
// took anything: a '?' and what followed went to the driver as connection
// parameters ahead of the daemon's own, a file: URI likewise, and a relative
// path made a file wherever the daemon had been started.
func TestSetupWizardTakesAPathForSQLite(t *testing.T) {
	h, token := optionsWizard(t)
	dir := t.TempDir()
	post := func(path string) (loc string) {
		t.Helper()
		res := wizardPost(h.AdminSetupSaveDB, url.Values{"driver": {"sqlite"}, "sqlite_path": {path}}, token, "")
		if res.StatusCode != http.StatusFound {
			t.Fatalf("%q: status %d", path, res.StatusCode)
		}
		return res.Header.Get("Location")
	}
	errOf := func(loc string) string {
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		return u.Query().Get("err")
	}
	entries := func() string {
		t.Helper()
		es, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range es {
			names = append(names, e.Name())
		}
		return strings.Join(names, " ")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct{ path, want string }{
		{filepath.Join(dir, "a.sqlite") + "?_pragma=foreign_keys(0)", "connection parameters"},
		{filepath.Join(dir, "b.sqlite") + "?vfs=memdb", "connection parameters"},
		{"file:" + filepath.Join(dir, "c.sqlite"), "not a file: URI"},
		{"FILE:" + filepath.Join(dir, "d.sqlite") + "?mode=rwc", "connection parameters"},
		{"rel-setup-test/e.sqlite", "must be absolute"},
		{"e.sqlite", "must be absolute"},
		{filepath.Join(dir, "f\n.sqlite"), "control character"},
	} {
		e := errOf(post(c.path))
		if !strings.Contains(e, c.want) {
			t.Errorf("%q: the wizard answered %q, want a refusal naming %q", c.path, e, c.want)
		}
	}
	if got := entries(); got != "" {
		t.Errorf("the refused paths left files behind: %s", got)
	}
	for _, name := range []string{"rel-setup-test", "e.sqlite"} {
		if _, err := os.Stat(filepath.Join(wd, name)); err == nil {
			_ = os.RemoveAll(filepath.Join(wd, name))
			t.Errorf("a relative path made %s in the directory the test runs in", name)
		}
	}

	// A path is taken, and is the path the file is at -- written the long
	// way round included.
	if e := errOf(post(filepath.Join(dir, "sub", "..", "ok.sqlite"))); e != "" {
		t.Fatalf("a plain absolute path was refused: %q", e)
	}
	if got := entries(); !strings.Contains(got, "ok.sqlite") || strings.Contains(got, "sub") {
		t.Errorf("after a plain path the directory holds %q, want ok.sqlite and no sub", got)
	}
}
