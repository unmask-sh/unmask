package handlers

import (
	"os"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// Same rationale as nginxconf's TestMain: the auto-from-UA bypass derivation
// must not ride the embedded snapshot's real age inside tests.  Handlers
// render and match through nginxconf, so the pin applies here too.
func TestMain(m *testing.M) {
	restore := nginxconf.SetSnapshotDataAtForTests(func() time.Time { return time.Time{} })
	// No test re-executes the test binary.  The wizard's switch of database
	// schedules a syscall.Exec of os.Args a few seconds later, which starts
	// the whole suite over in place: in CI, over and over until the package
	// timed out, with nothing pointing at the cause.  The tests that pin the
	// trigger count the calls instead.
	scheduleReexecFn = func() {}
	code := m.Run()
	restore()
	os.Exit(code)
}
