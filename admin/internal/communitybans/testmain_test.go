package communitybans

import (
	"os"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

// The tests' servers listen on loopback, which the outbound policy refuses
// by default (internal/outbound); the suite opens it -- as a test-only
// allowance, which a settings save in the suite cannot take away.
//
// And it reaches nothing else.  The client's settings name the hub by
// default, so a test that sets a feed URL and forgets the register URL, and
// then runs what a daemon runs at its start, registers with the hub: a
// token there for an install that does not exist, counted among the installs
// that are running.  One did.  With this, such a test gets an error.
func TestMain(m *testing.M) {
	outbound.SetLoopbackForTests(true)
	outbound.SetOnlyLoopbackForTests(true)
	os.Exit(m.Run())
}
