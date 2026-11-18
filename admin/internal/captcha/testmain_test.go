package captcha

import (
	"os"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

// The suite reaches loopback and nothing else
// (outbound.SetOnlyLoopbackForTests): the package knows the CAPTCHA providers' verify endpoints by their real addresses
// whenever a test names no other, and a test that forgot to name one would
// reach it.
func TestMain(m *testing.M) {
	outbound.SetOnlyLoopbackForTests(true)
	os.Exit(m.Run())
}
