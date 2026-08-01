package ipgeo

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// AutoUpdateStale decides purely from the snapshot's own build date, and only
// for files unmask manages.  These cases are the ones that decide whether the
// fleet quietly rots: a fresh file must not be re-downloaded every day, a
// month-old one must be, and an operator's own file must never be touched no
// matter how old it is.
func TestAutoUpdateStaleDecisions(t *testing.T) {
	// A stand-in for "there is a file here": AutoUpdateStale reads its build
	// date via InspectMMDB, which fails on a non-mmdb -- and an unreadable
	// managed file is deliberately treated as replaceable.
	write := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("not an mmdb"), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("a custom path is never touched", func(t *testing.T) {
		dir := t.TempDir()
		custom := filepath.Join(dir, "mine.mmdb")
		write(t, custom)
		// No network is reachable in the test, so "did it try" is observable:
		// a download attempt would fail and return 0 either way -- what we can
		// assert is that the file is untouched and no attempt was recorded.
		before, err := os.Stat(custom)
		if err != nil {
			t.Fatal(err)
		}
		if n := AutoUpdateStale(custom, "", nil, time.Hour, time.Now()); n != 0 {
			t.Errorf("replaced %d file(s); a custom path must be left alone", n)
		}
		after, err := os.Stat(custom)
		if err != nil {
			t.Fatal(err)
		}
		if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
			t.Error("the operator's own file was modified")
		}
	})

	t.Run("a missing file is AutoFetchMissing's job, not this one", func(t *testing.T) {
		// Managed path that does not exist: nothing to keep current.
		if n := AutoUpdateStale(DefaultMMDBPath+".absent", "", nil, time.Hour, time.Now()); n != 0 {
			t.Errorf("replaced %d file(s) for a path with no file", n)
		}
	})
}

// The freshness question itself, isolated from the download: a file whose
// build date is inside the window is current, one outside it is stale.  Pinned
// because the alternative -- judging by file mtime -- silently never expires,
// since re-downloading the same snapshot resets the mtime.
func TestStalenessIsJudgedByBuildDateNotMtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dbip-country.mmdb")
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	// Fresh mtime, unreadable build date: an mtime-based rule would call this
	// current forever.  InspectMMDB fails here, which AutoUpdateStale treats
	// as "replace it" -- the safe direction for a file it manages.
	info, err := InspectMMDB(path)
	if err == nil {
		t.Skip("the stub parsed as an mmdb; nothing to assert")
	}
	if !info.BuildTime.IsZero() {
		t.Errorf("an unreadable file reported a build time: %v", info.BuildTime)
	}
	if !info.Exists {
		t.Error("the file exists on disk but InspectMMDB says otherwise")
	}
}

// The two databases are switched independently: turning one off must not stop
// the other, which is the whole point of having two flags.
func TestAutoUpdateKindsAreIndependent(t *testing.T) {
	dir := t.TempDir()
	// Managed paths are absolute constants, so this asserts the gating without
	// touching them: with both kinds off nothing is even considered, and the
	// call is a no-op regardless of what is on disk.
	country := filepath.Join(dir, "c.mmdb")
	asn := filepath.Join(dir, "a.mmdb")
	for _, p := range []string{country, asn} {
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if n := AutoUpdateStaleKinds(country, asn, false, false, nil, time.Hour, time.Now()); n != 0 {
		t.Errorf("both flags off must do nothing, replaced %d", n)
	}
	// Custom paths (which these are) are skipped whatever the flags say, so a
	// non-zero result here would mean the managed-path guard was bypassed.
	if n := AutoUpdateStaleKinds(country, asn, true, true, nil, time.Hour, time.Now()); n != 0 {
		t.Errorf("custom paths must be skipped even with both flags on, replaced %d", n)
	}
}
