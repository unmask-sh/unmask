package notifier

import (
	"os"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

// The tests' servers listen on loopback, which the outbound policy refuses
// by default (internal/outbound); the suite opens it -- as a test-only
// allowance, which a settings save in the suite cannot take away.
func TestMain(m *testing.M) {
	outbound.SetLoopbackForTests(true)
	// And it reaches nothing else (outbound.SetOnlyLoopbackForTests): the
	// code under test knows the services it calls by their real addresses
	// whenever a test names no other, and a test that forgot to name one
	// has reached them (internal/communitybans' TestMain tells of one).
	outbound.SetOnlyLoopbackForTests(true)
	os.Exit(m.Run())
}
