package advisor

import (
	"os"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

// The candidate list is computed behind the caller, which waits computeWait
// for it before answering without one.  A CI runner can take longer than
// the two seconds over a test database, and a test that reads the list it
// just seeded would then get ErrComputing instead.  The tests wait for the
// list; the tests of the notice itself set the wait to zero.
func TestMain(m *testing.M) {
	restore := SetComputeWaitForTest(2 * time.Minute)
	// The suite reaches loopback and nothing else
	// (outbound.SetOnlyLoopbackForTests): the advisor knows the AI
	// providers by their real addresses whenever a test names no other, and
	// a test that forgot to name one would call them.
	outbound.SetOnlyLoopbackForTests(true)
	code := m.Run()
	restore()
	os.Exit(code)
}
