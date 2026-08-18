package nginxconf

import (
	"os"
	"testing"
	"time"
)

// The auto-from-UA derivation (autobypass.go) reads the embedded snapshot's
// real vintage, which ages on its own.  Tests therefore default it to "no
// dated data" -- derivation off, the manual axis every pre-existing test
// specifies -- and tests OF the derivation pin a fresh vintage explicitly
// (pinFreshSnapshot).  Without this, the suite's behavior would change by
// itself ~30 days after each embed refresh.
func TestMain(m *testing.M) {
	restore := SetSnapshotDataAtForTests(func() time.Time { return time.Time{} })
	code := m.Run()
	restore()
	os.Exit(code)
}
