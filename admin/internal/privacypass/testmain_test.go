package privacypass

import (
	"os"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

// The tests' servers listen on loopback, which the outbound policy refuses
// by default (internal/outbound); the suite opens it.
func TestMain(m *testing.M) {
	outbound.SetPolicy(outbound.Policy{AllowLoopback: true})
	os.Exit(m.Run())
}
