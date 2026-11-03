package events

import (
	"io"
	"log"
	"os"
	"testing"
)

// The package logs through the standard logger, and under test it logs what
// it would in production: a flush against a database the test closed, a
// prune's progress.  go test prints it all exactly when a test fails, around
// the one line that says what did.  Dropped unless asked for;
// UNMASK_TEST_LOG=1 keeps it.
func TestMain(m *testing.M) {
	if os.Getenv("UNMASK_TEST_LOG") == "" {
		log.SetOutput(io.Discard)
	}
	os.Exit(m.Run())
}
