package browsermajors

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
	os.Exit(m.Run())
}
