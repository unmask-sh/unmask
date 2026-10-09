package advisor

import (
	"os"
	"testing"
	"time"
)

// The candidate list is computed behind the caller, which waits computeWait
// for it before answering without one.  A CI runner can take longer than
// the two seconds over a test database, and a test that reads the list it
// just seeded would then get ErrComputing instead.  The tests wait for the
// list; the tests of the notice itself set the wait to zero.
func TestMain(m *testing.M) {
	restore := SetComputeWaitForTest(2 * time.Minute)
	code := m.Run()
	restore()
	os.Exit(code)
}
