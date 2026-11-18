package ipgeo

import (
	"os"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

// The suite reaches loopback and nothing else
// (outbound.SetOnlyLoopbackForTests): the package knows where the GeoIP databases are published
// whenever a test names no other, and a test that forgot to name one would
// reach it.
func TestMain(m *testing.M) {
	outbound.SetOnlyLoopbackForTests(true)
	os.Exit(m.Run())
}
