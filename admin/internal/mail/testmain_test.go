package mail

import (
	"os"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

// The suite reaches loopback and nothing else
// (outbound.SetOnlyLoopbackForTests): the package dials whatever relay a test's configuration names
// whenever a test names no other, and a test that forgot to name one would
// reach it.
func TestMain(m *testing.M) {
	outbound.SetOnlyLoopbackForTests(true)
	os.Exit(m.Run())
}
