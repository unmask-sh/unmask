// Package testutil holds helpers the tests of several packages share.
package testutil

import (
	"os"
	"testing"
)

// SocketDir returns a directory whose path is short enough for a unix socket
// to be bound under it, removed when the test ends.
//
// A socket address holds 108 bytes on Linux (sun_path), and t.TempDir() sits
// under TMPDIR, which some environments set deep enough for "<dir>/log.sock"
// to run past that: every test that binds a socket then fails on the bind.
// So the directory is made under /tmp when that can be written to, and under
// the usual temporary directory otherwise.
func SocketDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "unmask-sock-")
	if err != nil {
		if dir, err = os.MkdirTemp("", "unmask-sock-"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
