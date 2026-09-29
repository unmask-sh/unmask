package handlers

import (
	"os"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// Same rationale as nginxconf's TestMain: the auto-from-UA bypass derivation
// must not ride the embedded snapshot's real age inside tests.  Handlers
// render and match through nginxconf, so the pin applies here too.
//
// The schema update tests start this test binary where the daemon starts
// `unmask migrate` (TestSchemaUpdateHelper); it is not named "unmask", so the
// check for whether a run's process is alive is told what to look for.
func TestMain(m *testing.M) {
	restore := nginxconf.SetSnapshotDataAtForTests(func() time.Time { return time.Time{} })
	db.AddRunnerNameForTest(".test")
	code := m.Run()
	restore()
	os.Exit(code)
}
