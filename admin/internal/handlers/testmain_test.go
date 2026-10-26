package handlers

import (
	"os"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
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
	// The ban candidates are computed behind the page, which waits two
	// seconds for them before it answers without a list.  A CI runner can
	// take longer than that over a test database, and every test that reads
	// the list off the page would then see the "being computed" notice
	// instead.  The tests wait for the list; the one test of the notice
	// sets the wait to zero itself.
	restoreWait := advisor.SetComputeWaitForTest(2 * time.Minute)
	// The renders here read the fail-safe marker from the package's render
	// dir as well as their own; the test host's must stay out of it.
	pkgDir, err := os.MkdirTemp("", "unmask-failsafe-")
	if err != nil {
		panic(err)
	}
	nginxconf.FailsafePackageDir = pkgDir
	code := m.Run()
	_ = os.RemoveAll(pkgDir)
	restoreWait()
	restore()
	os.Exit(code)
}
