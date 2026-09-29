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
	code := m.Run()
	restore()
	os.Exit(code)
}
