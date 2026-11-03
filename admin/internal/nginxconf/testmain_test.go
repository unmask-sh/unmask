package nginxconf

import (
	"os"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

// The auto-from-UA derivation (autobypass.go) reads the embedded snapshot's
// real vintage, which ages on its own.  Tests therefore default it to "no
// dated data" -- derivation off, the manual axis every pre-existing test
// specifies -- and tests OF the derivation pin a fresh vintage explicitly
// (pinFreshSnapshot).  Without this, the suite's behavior would change by
// itself ~30 days after each embed refresh.
func TestMain(m *testing.M) {
	restore := SetSnapshotDataAtForTests(func() time.Time { return time.Time{} })
	// The fail-safe marker counts from the package's render dir as well as
	// the render's own; a marker left on the test host must not make every
	// render in the suite the degraded one.
	pkgDir, err := os.MkdirTemp("", "unmask-failsafe-")
	if err != nil {
		panic(err)
	}
	FailsafePackageDir = pkgDir
	// The tests' servers listen on loopback, which the outbound policy
	// refuses by default (internal/outbound); the suite opens it.
	outbound.SetPolicy(outbound.Policy{AllowLoopback: true})
	code := m.Run()
	_ = os.RemoveAll(pkgDir)
	restore()
	os.Exit(code)
}
